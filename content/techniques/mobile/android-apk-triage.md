---
title: "Android APK Triage - First 10 Minutes on an Unknown APK"
category: mobile
subcategory: android-static
type: technique
tags: [apk, android, apktool, jadx, jadx-gui, apkleaks, aapt, androidmanifest, dex, triage, static-analysis, unzip, exported, debuggable, allowbackup, grep]
difficulty: easy
summary: "Unpack, decompile and grep an APK in a fixed order so you find the flag path before wasting time reversing the wrong class."
when_to_use:
  - "You are handed a .apk / .xapk / .aab and have no idea what it does"
  - "A mobile challenge says 'find the flag inside the app'"
  - "You need the manifest, entry points and embedded assets fast"
tools: [apktool, jadx, apkleaks, aapt2, unzip, dex2jar, ripgrep]
related: [android-static-secrets, android-smali-patching, android-native-jni, android-deobfuscation]
---

## TL;DR

An APK is a ZIP. Three tools give three different views: `unzip` gives raw assets,
`apktool` gives smali + decoded resources (the only view you can rebuild from),
`jadx` gives readable Java (the only view you can read fast). Run all three,
then grep. 80% of CTF mobile challenges die to `jadx` + `grep -R flag`.

## Recognise it

- File magic is `PK\x03\x04`; `unzip -l app.apk` lists `classes.dex`, `AndroidManifest.xml`, `res/`, `lib/`.
- `.xapk` / `.apks` / `.apkm` are ZIPs **of** APKs (split APKs) - unzip once more, the code is in `base.apk`.
- `.aab` (App Bundle) has `base/dex/classes.dex` instead - use `bundletool build-apks` or just read the dex directly.
- Multiple `classes.dex`, `classes2.dex`... means multidex; jadx handles all of them, `dex2jar` needs each one.
- A `lib/` directory means native code - see `android-native-jni`.

## Theory

The three views and what each is good for:

| View | Command | Gives you | Rebuildable |
|---|---|---|---|
| ZIP | `unzip -d out app.apk` | assets, raw `resources.arsc`, native `.so`, `META-INF` signature | yes (but manifest is binary XML) |
| apktool | `apktool d app.apk` | smali, decoded `AndroidManifest.xml`, `res/values/strings.xml` | **yes** - this is the patching view |
| jadx | `jadx -d out app.apk` | Java source (lossy, may fail on obfuscated/packed code) | no |

`AndroidManifest.xml` inside the ZIP is **binary XML** (AXML). `cat` on it gives garbage.
Decode with `apktool d`, `aapt2 dump xmltree`, or `androguard`.

The signature lives in `META-INF/`: `*.RSA`/`*.DSA`/`*.EC` (v1 JAR signing) plus an
APK Signing Block appended before the central directory (v2/v3/v4). Any modification
invalidates it, which is why you must re-sign after patching.

## Attack

1. **Identify** - `file`, `unzip -l`, size, split or not.
2. **Metadata** - package name, versions, permissions, launchable activity:
   `aapt2 dump badging app.apk`.
3. **Decode** - `apktool d` and `jadx -d` into two separate directories.
4. **Manifest review** - the checklist below.
5. **Grep pass 1** - flag-shaped strings, then secrets.
6. **Assets** - `assets/`, `res/raw/`, `res/values/strings.xml`, any `.db`, `.json`, `.js`.
7. **Native** - `lib/*/*.so` -> `strings`, then Ghidra if needed.
8. **Entry points** - launcher activity, exported components, `onCreate`, `attachBaseContext`
   (a non-trivial `attachBaseContext` in the Application class means a packer).

### Manifest checklist

Open `out-apktool/AndroidManifest.xml` and answer:

- `package=` - the package id you will need for every `adb`/`frida` command.
- `android:debuggable="true"` - you can `run-as` the app and pull `/data/data` without root.
- `android:allowBackup="true"` - `adb backup` may dump app data (legacy devices).
- `android:usesCleartextTraffic="true"` - HTTP endpoints exist, intercept them.
- `android:networkSecurityConfig="@xml/network_security_config"` - read that file, it lists
  pinned certs and cleartext-permitted domains.
- `android:exported="true"` (or any `<intent-filter>` on pre-API-31) on
  `activity` / `service` / `receiver` / `provider` - attack surface, see `android-exported-components`.
- `<uses-permission>` list - `READ_EXTERNAL_STORAGE`, `INTERNET`, custom permissions.
- `<provider android:authorities="...">` - authority string for `content://` queries.
- `android:minSdkVersion` / `targetSdkVersion` - decides which mitigations apply
  (user CA trust broke at 24, `exported` became mandatory at 31).
- `<application android:name="...">` - the Application subclass, first code to run.
- `<meta-data>` - frequently holds API keys (Maps, AdMob, Firebase).

### Grep order (do these literally, in this order)

```bash
# 1. the lazy win: flag format anywhere in the decompiled tree
grep -rIn -E 'flag\{|FLAG\{|CTF\{|[A-Za-z0-9_]{3,10}\{[A-Za-z0-9_!@#$%^&*-]{5,}\}' out-jadx/ out-apktool/

# 2. base64 blobs longer than 24 chars (often the encoded flag)
grep -rIoE '[A-Za-z0-9+/]{24,}={0,2}' out-apktool/res out-apktool/assets | sort -u | head -50

# 3. every URL and host
grep -rIoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' out-jadx/ | sort -u

# 4. credential-shaped identifiers
grep -rIn -iE '(api[_-]?key|secret|passwd|password|token|bearer|authorization|private[_-]?key)' out-jadx/sources | head -80

# 5. crypto usage - tells you which class does the checking
grep -rIn -E 'Cipher\.getInstance|SecretKeySpec|IvParameterSpec|MessageDigest|Base64\.(decode|encode)' out-jadx/sources

# 6. native bridge
grep -rIn -E 'System\.loadLibrary|native |JNI' out-jadx/sources

# 7. runtime string building (obfuscation giveaway)
grep -rIn -E 'StringBuilder|char\[\]|\.toCharArray\(\)|\^ *0x' out-jadx/sources | head -40
```

## Code

```python
#!/usr/bin/env python3
"""apk_triage.py - one-shot APK triage: manifest facts + interesting files + grep hits.

Pure stdlib. Reads the APK as a ZIP and parses Android binary XML (AXML) well enough
to recover element names, attribute names and string values from AndroidManifest.xml.

Usage: python3 apk_triage.py app.apk
"""
from __future__ import annotations

import re
import sys
import zipfile
from typing import Iterator

INTERESTING_EXT = (".json", ".db", ".sqlite", ".js", ".html", ".txt", ".pem",
                   ".crt", ".cer", ".key", ".properties", ".yml", ".yaml", ".xml")
SECRET_RE = re.compile(
    rb"(?i)(api[_-]?key|secret|password|passwd|token|bearer|private[_-]?key"
    rb"|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{4,}")
FLAG_RE = re.compile(rb"(?i)[a-z0-9_]{2,12}\{[ -~]{4,80}\}")

# --- minimal AXML string-pool reader -----------------------------------------
RES_STRING_POOL = 0x0001


def _u32(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 4], "little")


def _u16(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 2], "little")


def axml_strings(data: bytes) -> list[str]:
    """Return every string in the first string pool of an AXML/ARSC chunk."""
    out: list[str] = []
    if len(data) < 16:
        return out
    off = 8  # skip file header (type, headerSize, size)
    while off + 8 <= len(data):
        ctype = _u16(data, off)
        csize = _u32(data, off + 4)
        if csize <= 0 or off + csize > len(data):
            break
        if ctype == RES_STRING_POOL:
            count = _u32(data, off + 8)
            strings_start = _u32(data, off + 20)
            flags = _u32(data, off + 16)
            is_utf8 = bool(flags & (1 << 8))
            base = off + strings_start
            for i in range(count):
                idx_off = off + 28 + 4 * i
                if idx_off + 4 > len(data):
                    break
                sp = base + _u32(data, idx_off)
                if sp >= len(data):
                    break
                if is_utf8:
                    # two varint-ish lengths (chars, bytes) then UTF-8 bytes
                    n = data[sp]
                    sp += 2 if n & 0x80 else 1
                    m = data[sp]
                    if m & 0x80:
                        blen = ((m & 0x7F) << 8) | data[sp + 1]
                        sp += 2
                    else:
                        blen = m
                        sp += 1
                    out.append(data[sp:sp + blen].decode("utf-8", "replace"))
                else:
                    clen = _u16(data, sp)
                    sp += 2
                    if clen & 0x8000:
                        clen = ((clen & 0x7FFF) << 16) | _u16(data, sp)
                        sp += 2
                    out.append(data[sp:sp + clen * 2].decode("utf-16-le", "replace"))
            return out
        off += csize
    return out


MANIFEST_FLAGS = ("debuggable", "allowBackup", "usesCleartextTraffic",
                  "networkSecurityConfig", "exported", "authorities",
                  "android.permission", "Activity", "Service", "Receiver", "Provider")


def iter_hits(name: str, blob: bytes) -> Iterator[str]:
    for rx, label in ((FLAG_RE, "FLAG"), (SECRET_RE, "SECRET"), (URL_RE, "URL")):
        for m in set(rx.findall(blob)):
            val = m if isinstance(m, bytes) else m[0]
            yield f"[{label}] {name}: {val.decode('utf-8', 'replace')[:160]}"


def triage(path: str) -> int:
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        print(f"== {path}: {len(names)} entries ==")
        dex = [n for n in names if n.endswith(".dex")]
        libs = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and "/" in n[4:]})
        print(f"dex files : {', '.join(dex) or 'none'}")
        print(f"native abis: {', '.join(libs) or 'none'}")

        if "AndroidManifest.xml" in names:
            pool = axml_strings(z.read("AndroidManifest.xml"))
            print("\n-- manifest strings of interest --")
            for s in pool:
                if any(k.lower() in s.lower() for k in MANIFEST_FLAGS) or s.startswith("android.permission"):
                    print("  " + s)

        print("\n-- interesting files --")
        for n in names:
            if n.lower().endswith(INTERESTING_EXT) and not n.startswith("res/color"):
                info = z.getinfo(n)
                print(f"  {info.file_size:>9} {n}")

        print("\n-- string hits --")
        seen: set[str] = set()
        for n in names:
            if z.getinfo(n).file_size > 8 * 1024 * 1024:
                continue
            try:
                blob = z.read(n)
            except (RuntimeError, zipfile.BadZipFile):
                continue
            for line in iter_hits(n, blob):
                if line not in seen:
                    seen.add(line)
                    print("  " + line)
        print(f"\n{len(seen)} unique hits")
    return 0


def _selftest() -> None:
    import io
    import os
    import tempfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("assets/config.json", b'{"api_key":"AIza' + b"A" * 35 + b'","url":"https://ctf.example/api"}')
        z.writestr("res/raw/note.txt", b"flag{triage_works}")
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.apk")
        with open(p, "wb") as fh:
            fh.write(buf.getvalue())
        triage(p)
    print("selftest ok")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _selftest()
    else:
        sys.exit(triage(sys.argv[1]))
```

### The command sequence

```bash
# identify: is it really an APK, is it a split bundle
file app.apk && unzip -l app.apk | head -40

# package id, version, permissions, launchable activity - no decode needed
aapt2 dump badging app.apk | grep -E 'package|launchable|uses-permission|sdkVersion'

# apktool: smali + decoded resources (the rebuildable view)
apktool d -f -o out-apktool app.apk

# jadx: readable java; --deobf renames a/a/a, -r skips resources for speed
jadx -d out-jadx --deobf --show-bad-code app.apk

# raw zip view for assets and native libs
mkdir -p out-zip && unzip -q -o app.apk -d out-zip

# known-secret scanner with the standard ruleset
apkleaks -f app.apk -o apkleaks.txt

# what native libs ship and for which abi
find out-zip/lib -name '*.so' -exec sh -c 'echo "== $1"; file "$1"' _ {} \;

# strings from every native lib at once
find out-zip/lib -name '*.so' -exec strings -n 8 {} + | sort -u > native-strings.txt
```

## Variants & pitfalls

- **jadx produces empty/garbage classes** -> the app is packed or uses a non-standard dex.
  Fall back to smali (apktool never fails) and see `android-deobfuscation`.
- **`apktool d` fails on resources** -> `apktool d -r app.apk` (skip resources, keep smali)
  or `--only-main-classes`.
- **Split APKs** - `base.apk` has the code, `split_config.arm64_v8a.apk` has the `.so`,
  `split_config.xxhdpi.apk` has drawables. Merge before rebuilding, or install with
  `adb install-multiple`.
- **`resources.arsc` stored uncompressed** on newer builds; re-zipping it compressed breaks
  install on Android 11+. Use `apktool b` (it handles this) rather than hand-zipping.
- **The flag is in `res/values/strings.xml` but renamed**, e.g. `<string name="app_desc">`.
  Dump all strings, do not only grep for `flag`.
- **Assets are encrypted** - look for the decryptor in `Application.onCreate` or a
  `native` method; hook it at runtime instead of reimplementing.
- **`classes.dex` is a stub** (a few hundred bytes, only the packer's Application class)
  -> dynamic dex loading, dump from memory.
- Never trust the file extension: some CTFs hand you an `.apk` that is actually a `.aab` or
  a renamed JAR.

## Tools

- `apktool` - decode/rebuild, smali, binary XML.
- `jadx` / `jadx-gui` - dex to Java; `--deobf` for renamed identifiers.
- `apkleaks` - regex secret scanner tuned for APKs.
- `aapt2` - `dump badging`, `dump xmltree`, no full decode needed.
- `dex2jar` + `jd-gui` / `procyon` - second opinion when jadx chokes.
- `androguard` - Python API for manifest and dex analysis.
- `ripgrep` - the actual workhorse of triage.

## References

- Android Open Source Project documentation on APK format and app signing.
- `apktool` project documentation (Framework and rebuild notes).
- `jadx` project README for CLI flags.
