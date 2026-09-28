---
title: "Smali Patching - Read, Patch, Rebuild and Re-sign an APK"
category: mobile
subcategory: android-static
type: technique
tags: [smali, dalvik, apktool, android, patching, apksigner, zipalign, keytool, jarsigner, baksmali, dex, bytecode, crackme, license-check, rebuild]
difficulty: medium
summary: "Read Dalvik bytecode well enough to invert a check, then rebuild and re-sign the APK so it installs."
when_to_use:
  - "A check returns false and you want it to return true without solving it"
  - "jadx output is unusable but apktool smali is clean"
  - "You need to inject logging or a Toast into a released app"
tools: [apktool, apksigner, zipalign, keytool, jadx, baksmali]
related: [android-apk-triage, android-ssl-pinning-bypass, android-root-detection-bypass, android-frida-basics]
---

## TL;DR

`apktool d` -> edit `.smali` -> `apktool b` -> `zipalign` -> `apksigner sign`.
Smali is verbose but simple: registers `v0..vN` (locals) and `p0..pN` (parameters,
`p0` is `this` in an instance method), one operation per line, explicit types.
To defeat a boolean check you usually only need `const/4 v0, 0x1` + `return v0`.

## Recognise it

- `jadx` shows `if (!checkLicense()) { finish(); }` and you just want it gone.
- The check is a `native` call you cannot easily emulate -> patch the Java caller instead.
- The app has anti-Frida measures, so runtime hooking is noisier than a static patch.
- You want the patch to persist across reboots / be shippable as a modified APK.

## Theory

### Register model

- Dalvik is register-based, not stack-based.
- `.registers N` = total registers in the method (locals + params).
  `.locals N` = locals only; params then live in the top registers, named `p0..pk`.
- Instance method: `p0` = `this`, `p1` = first argument. Static method: `p0` = first argument.
- `v0` is the first local. `v` and `p` numbering can overlap: with `.locals 3` in an
  instance method taking one `int`, `p0 == v3` and `p1 == v4`.

### Type descriptors

| Descriptor | Java |
|---|---|
| `V` | void |
| `Z` | boolean |
| `B` `S` `C` `I` `J` `F` `D` | byte short char int long float double |
| `Ljava/lang/String;` | object, slash-separated, trailing `;` |
| `[I` | int[] |
| `([Ljava/lang/String;I)Z` | `boolean m(String[], int)` |

`J` and `D` occupy **two** registers (`v0` holds the pair `v0:v1`).

### Instructions you actually need

```smali
const/4 v0, 0x1              # small int literal (-8..7) into v0
const/16 v0, 0x100           # 16-bit literal
const-string v0, "flag"      # string constant
move-result v0               # grab the int/ref returned by the previous invoke-*
move-result-object v0        # grab an object result
return-void                  # return from a V method
return v0                    # return an int/boolean
return-object v0             # return an object
if-eqz v0, :cond_0           # jump if v0 == 0  (i.e. if false / null)
if-nez v0, :cond_0           # jump if v0 != 0
if-eq v0, v1, :cond_0        # jump if equal
goto :goto_0                 # unconditional jump
invoke-virtual {p0, v1}, Lcom/x/A;->check(Ljava/lang/String;)Z
invoke-static  {v0}, Lcom/x/A;->calc(I)I
invoke-direct  {p0}, Ljava/lang/Object;-><init>()V
iget-object v0, p0, Lcom/x/A;->name:Ljava/lang/String;   # read instance field
iput-boolean v0, p0, Lcom/x/A;->ok:Z                     # write instance field
sget-object v0, Lcom/x/A;->TAG:Ljava/lang/String;        # read static field
new-instance v0, Ljava/lang/StringBuilder;
```

`invoke-*/range {v0 .. v5}` is the same call with many registers.

### The three patches that solve most challenges

**1. Force a boolean method to return true**

```smali
.method private checkLicense(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```

Delete the original body entirely; `.locals 1` is enough because you only use `v0`.

**2. Invert a branch** - change `if-eqz` to `if-nez` (or vice versa). One-character edit,
no register bookkeeping, cannot break verification.

**3. Neutralise a call** - replace

```smali
invoke-virtual {p0}, Lcom/x/A;->exitIfRooted()V
```

with nothing (for a `V` method) or, if a result is consumed, keep the `move-result`
and feed it a constant:

```smali
const/4 v0, 0x0
# (deleted invoke + move-result v0)
```

## Attack

1. `apktool d -f -o out app.apk`.
2. Find the class: jadx gives you the readable name, then
   `grep -rn "checkLicense" out/smali*/`.
3. Edit the `.smali` file. Keep `.locals` >= the highest `vN` you use.
4. `apktool b out -o patched.apk`.
5. `zipalign -p -f 4 patched.apk aligned.apk`.
6. Create a debug keystore once, then `apksigner sign`.
7. `adb install -r signed.apk` (uninstall first if the original signature differs).

## Code

```bash
#!/bin/sh
# patch-apk.sh - full decode -> patch -> rebuild -> sign -> install cycle
set -eu

APK="${1:?usage: patch-apk.sh app.apk [package.name]}"
PKG="${2:-}"
WORK=out-apktool
KS=debug.keystore
KSPASS=android
ALIAS=androiddebugkey

# 1. decode: -f overwrites a previous run, -o fixes the output dir
apktool d -f -o "$WORK" "$APK"

echo ">>> edit the smali under $WORK/smali*/ now, then press enter"
read -r _

# 2. rebuild. --use-aapt2 avoids old aapt resource bugs on modern APKs
apktool b "$WORK" -o unsigned.apk --use-aapt2

# 3. align BEFORE signing with apksigner (v2+ signatures cover the aligned file)
#    -p aligns .so files to the page boundary, -f overwrites, 4 = 4-byte alignment
zipalign -p -f 4 unsigned.apk aligned.apk

# 4. one-off debug keystore: RSA 2048, 10000 days, non-interactive
if [ ! -f "$KS" ]; then
  keytool -genkeypair -v -keystore "$KS" -alias "$ALIAS" \
      -keyalg RSA -keysize 2048 -validity 10000 \
      -storepass "$KSPASS" -keypass "$KSPASS" \
      -dname "CN=Android Debug,O=Android,C=US"
fi

# 5. sign with v1+v2+v3 so it installs on every API level
apksigner sign --ks "$KS" --ks-pass "pass:$KSPASS" --key-pass "pass:$KSPASS" \
    --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
    --out signed.apk aligned.apk

# 6. prove it
apksigner verify --verbose --print-certs signed.apk

# 7. install (signature changed, so the old copy must go first)
if [ -n "$PKG" ]; then adb uninstall "$PKG" || true; fi
adb install -r signed.apk
```

### A Python helper that rewrites a method body for you

```python
#!/usr/bin/env python3
"""smali_patch.py - replace a smali method body with a constant return.

Handles Z/I/B/S/C (return v0), V (return-void) and object returns (return-object v0 = null).

Usage:
  python3 smali_patch.py out/smali/com/x/A.smali checkLicense true
  python3 smali_patch.py out/smali/com/x/A.smali isRooted false
"""
from __future__ import annotations

import re
import sys

METHOD_RE = re.compile(r"^\.method\s+(?P<mods>[\w $]*?)(?P<name>[\w$<>]+)\((?P<args>[^)]*)\)(?P<ret>\S+)\s*$")


def body_for(ret: str, value: bool) -> list[str]:
    if ret == "V":
        return ["    .locals 0", "    return-void"]
    if ret in ("Z", "B", "S", "C", "I"):
        return ["    .locals 1", f"    const/4 v0, 0x{1 if value else 0}", "    return v0"]
    if ret in ("J",):
        return ["    .locals 2", f"    const-wide/16 v0, 0x{1 if value else 0}", "    return-wide v0"]
    if ret in ("F", "D"):
        return ["    .locals 2", "    const-wide/16 v0, 0x0", "    return-wide v0"]
    # object / array return: return null, or an empty string when it is a String
    if ret == "Ljava/lang/String;":
        return ["    .locals 1", '    const-string v0, ""', "    return-object v0"]
    return ["    .locals 1", "    const/4 v0, 0x0", "    return-object v0"]


def patch(text: str, method: str, value: bool) -> tuple[str, int]:
    out: list[str] = []
    lines = text.splitlines()
    i = 0
    count = 0
    while i < len(lines):
        m = METHOD_RE.match(lines[i])
        if m and m.group("name") == method:
            sig = lines[i]
            j = i + 1
            while j < len(lines) and lines[j].strip() != ".end method":
                j += 1
            out.append(sig)
            out.extend(body_for(m.group("ret"), value))
            out.append(".end method")
            count += 1
            i = j + 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out) + "\n", count


SAMPLE = """.class public Lcom/x/A;
.super Ljava/lang/Object;

.method private checkLicense(Ljava/lang/String;)Z
    .locals 3

    invoke-static {}, Lcom/x/Net;->online()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    return v1

    :cond_0
    const/4 v1, 0x0

    return v1
.end method

.method public other()V
    .locals 0
    return-void
.end method
"""


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    path, method, val = argv[1], argv[2], argv[3].lower() in ("1", "true", "yes")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    new, n = patch(text, method, val)
    if not n:
        print(f"method {method} not found in {path}")
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    print(f"patched {n} method(s) named {method} in {path}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        patched, n = patch(SAMPLE, "checkLicense", True)
        assert n == 1, n
        assert "const/4 v0, 0x1" in patched
        assert "invoke-static" not in patched.split(".method public other")[0]
        assert "return-void" in patched  # the untouched method survived
        print(patched)
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Injecting a debug Toast (useful to prove your patch runs)

Insert at the top of a method with at least 3 free locals (bump `.locals`):

```smali
    .locals 4

    const-string v1, "patched build"

    const/4 v2, 0x1

    invoke-static {p0, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v3

    invoke-virtual {v3}, Landroid/widget/Toast;->show()V
```

`p0` must be a `Context` (it is, inside an `Activity` method). Logging is safer:

```smali
    const-string v1, "CTF"

    const-string v2, "reached checkLicense"

    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```

## Variants & pitfalls

- **`.locals` too small** -> `apktool b` succeeds but the app crashes with a verifier
  error at runtime. Always raise `.locals` when you add registers.
- **`const/4` only holds -8..7.** Use `const/16` for up to 0x7FFF, `const` for 32-bit.
- **Registers v0-v15 only** for most `if-*` and `const/4` forms; higher registers need
  `/16` or `/32` variants or a `move/16`.
- **Rebuild fails on resources** -> `apktool b --use-aapt2`, or decode with `-r` and keep
  the original `resources.arsc` by rebuilding with `-c` (copy original files).
- **"Failed to install: INSTALL_FAILED_UPDATE_INCOMPATIBLE"** -> signature changed,
  `adb uninstall <pkg>` first.
- **"INSTALL_PARSE_FAILED_NO_CERTIFICATES"** -> you forgot `apksigner sign`, or you signed
  before `zipalign` with v2 only.
- **Android 11+ requires v2** - always enable v1+v2+v3.
- **The app checks its own signature** (`PackageManager.getPackageInfo(..., GET_SIGNATURES)`)
  -> patch that method too, or hook it with Frida.
- **Integrity-protected DEX** (checksum stored elsewhere) -> patch at runtime instead.
- Keep `apktool` framework files fresh: `apktool if framework-res.apk` for OEM ROMs.

## Tools

- `apktool` - decode/build, the only tool whose output round-trips.
- `baksmali` / `smali` - lower level, useful when apktool's resource handling gets in the way.
- `apksigner`, `zipalign`, `keytool` - Android SDK build-tools.
- `jadx` - to *find* the method; do the edit in smali.
- `apk-mitm` - automates the network-security-config patch + re-sign.

## References

- Android Open Source Project: Dalvik bytecode instruction reference.
- `smali`/`baksmali` project documentation for the assembler syntax.
- Android developer documentation on `apksigner` and APK Signature Scheme v2/v3.
