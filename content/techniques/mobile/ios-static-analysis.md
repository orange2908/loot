---
title: "iOS Static Analysis - IPA Structure, Mach-O, class-dump and Plists"
category: mobile
subcategory: ios-static
type: technique
tags: [ios, ipa, mach-o, class-dump, otool, lipo, codesign, entitlements, plist, plutil, keychain, fairplay, swift-demangle, ghidra, hopper, objective-c, dyld, frida-ios-dump]
difficulty: medium
summary: "Unpack an IPA, decrypt a FairPlay binary, recover Objective-C/Swift class metadata and mine plists, entitlements and the keychain."
when_to_use:
  - "You have an .ipa and need to know what the app does before running it"
  - "You need the class/method names to write Frida hooks"
  - "The flag is in a plist, an asset, or a hardcoded string in the binary"
tools: [class-dump, otool, lipo, codesign, plutil, ghidra, hopper, frida-ios-dump]
related: [ios-frida-runtime, mobile-traffic-interception, android-apk-triage, android-static-secrets]
---

## TL;DR

An IPA is a ZIP containing `Payload/App.app/`. The executable is a Mach-O (often a fat
binary). If `LC_ENCRYPTION_INFO_64.cryptid == 1` the text segment is FairPlay-encrypted
and static tools will show garbage - you must dump a decrypted copy from a jailbroken
device first. After that: `class-dump` for Objective-C, `swift demangle` for Swift,
`plutil` for binary plists, `codesign -d --entitlements` for capabilities.

## Recognise it

- `unzip -l app.ipa` -> `Payload/Foo.app/Foo`, `Info.plist`, `embedded.mobileprovision`,
  `_CodeSignature/CodeResources`, `Frameworks/`, `Assets.car`, `*.lproj/`.
- `file Payload/Foo.app/Foo` -> `Mach-O 64-bit executable arm64` or
  `Mach-O universal binary with 2 architectures`.
- `otool -l Foo | grep -A4 LC_ENCRYPTION_INFO` -> `cryptid 1` means encrypted.
- Strings are mostly Objective-C selectors (`viewDidLoad`, `setObject:forKey:`) or
  mangled Swift (`_$s3Foo11ViewControllerC5checkySbSSF`).

## Theory

### IPA layout

| Path | Contents |
|---|---|
| `Payload/Foo.app/Foo` | the Mach-O executable |
| `Payload/Foo.app/Info.plist` | bundle id, URL schemes, ATS config, permissions strings |
| `Payload/Foo.app/embedded.mobileprovision` | provisioning profile: a CMS blob wrapping a plist with entitlements and device UDIDs |
| `Payload/Foo.app/_CodeSignature/CodeResources` | per-file hashes (any edit breaks the signature) |
| `Payload/Foo.app/Frameworks/*.framework` | bundled dylibs, including the Swift runtime |
| `Payload/Foo.app/*.bundle` | resources; may contain their own plists and JS |
| `Payload/Foo.app/Assets.car` | compiled asset catalog (use `assetutil` or `acextract`) |
| `Payload/Foo.app/*.nib`, `*.storyboardc` | compiled UI, readable with `ibtool` |

### Mach-O

Header magic: `0xFEEDFACF` (64-bit LE) / `0xCAFEBABE` (fat). Load commands describe
segments (`__TEXT`, `__DATA`, `__LINKEDIT`), linked dylibs (`LC_LOAD_DYLIB`),
the entry point (`LC_MAIN`), the code signature (`LC_CODE_SIGNATURE`), and encryption
(`LC_ENCRYPTION_INFO_64`).

Useful sections:

- `__TEXT.__cstring` - C string literals.
- `__TEXT.__objc_methname` / `__objc_classname` - selector and class name pools.
- `__DATA.__objc_classlist`, `__objc_const`, `__objc_selrefs` - the Objective-C metadata
  that `class-dump` and Ghidra's ObjC analyzer read.
- `__TEXT.__swift5_types`, `__swift5_reflstr` - Swift reflection metadata.

### FairPlay

App Store binaries are encrypted per-device. `cryptid 1` with `cryptoff`/`cryptsize`
telling you which byte range. The kernel decrypts it into memory at launch, so the
standard recovery is to run the app on a jailbroken device and dump the decrypted pages
(`frida-ios-dump`, `bagbak`, `flexdecrypt`). Apps you build or side-load yourself have
`cryptid 0` and need none of this.

### Objective-C vs Swift

Objective-C keeps full class/method/ivar names in `__DATA` because the runtime needs them,
so `class-dump` reconstructs headers almost perfectly. Swift mangles names
(`$s` prefix) and, when using `final`/whole-module optimisation, devirtualises calls -
you get fewer symbols. `swift demangle` turns `$s3Foo11ViewControllerC5checkySbSSF`
into `Foo.ViewController.check(String) -> Swift.Bool`.

### Keychain

Items are stored in `/private/var/Keychains/keychain-2.db`, encrypted with keys protected
by the device's Secure Enclave. Accessibility classes decide when they are readable:

| Attribute | Readable |
|---|---|
| `kSecAttrAccessibleAlways` (deprecated) | always, even locked |
| `kSecAttrAccessibleAfterFirstUnlock` | after the first unlock since boot - the usual weak choice |
| `kSecAttrAccessibleWhenUnlocked` | only while unlocked |
| `...ThisDeviceOnly` variants | excluded from backups |
| `kSecAccessControlBiometryCurrentSet` | requires Face/Touch ID |

Static analysis tells you *which* class the app used; dumping needs a jailbroken device
(`objection ios keychain dump`).

## Attack

1. `unzip` the IPA; read `Info.plist` and the provisioning profile.
2. `lipo -info` / `lipo -thin arm64` to get a single-arch binary.
3. Check `cryptid`. If 1, dump a decrypted binary from a device before going further.
4. `class-dump` the headers; grep for suspicious selectors (`check`, `validate`, `flag`,
   `decrypt`, `isJailbroken`).
5. `strings` and `otool -s __TEXT __cstring`.
6. `codesign -d --entitlements :-` for capabilities (keychain groups, app groups,
   associated domains).
7. Load into Ghidra/Hopper, let the Objective-C analyser run, then read the interesting
   methods.
8. Write Frida hooks against the names you recovered (`ios-frida-runtime`).

## Code

### Unpack and inventory

```bash
#!/bin/sh
# ipa-triage.sh - unpack an ipa and print everything worth knowing
set -eu
IPA="${1:?usage: ipa-triage.sh app.ipa}"
OUT="${2:-ipa-out}"

rm -rf "$OUT" && mkdir -p "$OUT"
unzip -q "$IPA" -d "$OUT"

APPDIR="$(find "$OUT/Payload" -maxdepth 1 -name '*.app' | head -1)"
BIN="$APPDIR/$(basename "$APPDIR" .app)"
echo "== app: $APPDIR"
echo "== bin: $BIN"

# 1. architectures; thin to arm64 for analysis
file "$BIN"
lipo -info "$BIN" 2>/dev/null || true
lipo -thin arm64 "$BIN" -output "$OUT/bin.arm64" 2>/dev/null || cp "$BIN" "$OUT/bin.arm64"

# 2. is it fairplay-encrypted?
otool -l "$OUT/bin.arm64" | grep -A6 LC_ENCRYPTION_INFO || echo "no LC_ENCRYPTION_INFO (unencrypted)"

# 3. bundle metadata
plutil -convert xml1 -o - "$APPDIR/Info.plist" | \
  grep -E -A2 'CFBundleIdentifier|CFBundleVersion|CFBundleURLSchemes|NSAppTransportSecurity|NSAllowsArbitraryLoads|MinimumOSVersion|UIFileSharingEnabled'

# 4. every usage-description string (tells you which sensitive APIs it touches)
plutil -convert xml1 -o - "$APPDIR/Info.plist" | grep -B1 -A1 'UsageDescription'

# 5. entitlements from the signature and from the provisioning profile
codesign -d --entitlements :- "$APPDIR" 2>/dev/null || true
security cms -D -i "$APPDIR/embedded.mobileprovision" > "$OUT/profile.plist" 2>/dev/null || true
plutil -p "$OUT/profile.plist" 2>/dev/null | head -60 || true

# 6. linked libraries - third-party SDKs and pinning libs show up here
otool -L "$OUT/bin.arm64"

# 7. bundled frameworks
ls -1 "$APPDIR/Frameworks" 2>/dev/null || echo "no Frameworks"

# 8. every plist in the bundle, converted to xml
find "$APPDIR" -name '*.plist' -print0 | while IFS= read -r -d '' p; do
  echo "== $p"
  plutil -convert xml1 -o - "$p" 2>/dev/null | head -40
done

# 9. strings and urls
strings -a -n 6 "$OUT/bin.arm64" | sort -u > "$OUT/strings.txt"
grep -oE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' "$OUT/strings.txt" | sort -u | head -50
grep -iE 'api[_-]?key|secret|token|password|bearer' "$OUT/strings.txt" | head -40

echo "== done: see $OUT/strings.txt"
```

### Class metadata

```bash
# objective-c headers from the (decrypted) binary
class-dump -H -o headers/ bin.arm64
class-dump --list-arches app.ipa            # which slices exist

# grep the recovered interface for interesting selectors
grep -rn -iE 'flag|secret|token|verify|check|validat|decrypt|jailbr|pin' headers/ | head -40

# objective-c metadata straight from the mach-o, without class-dump
otool -o bin.arm64 | head -80
otool -v -s __DATA __objc_classlist bin.arm64 | head

# selector and class name pools
otool -v -s __TEXT __objc_methname bin.arm64 | head -50
otool -v -s __TEXT __objc_classname bin.arm64 | head -50

# c string literals
otool -v -s __TEXT __cstring bin.arm64 | head -60

# swift symbols, demangled
nm -gU bin.arm64 | grep '\$s' | head -40
nm -gU bin.arm64 | grep '\$s' | xargs -n1 swift demangle 2>/dev/null | head -40
# or:  swift demangle '$s3Foo14ViewControllerC5checkySbSSF'

# load commands: entry point, encryption, code signature, rpaths
otool -l bin.arm64 | grep -E 'cmd LC_|cryptid|cryptoff|cryptsize|path ' | head -60
```

### Decrypting a FairPlay binary (jailbroken device required)

```bash
# option 1: frida-ios-dump (runs the app, dumps decrypted pages, rebuilds an ipa)
#   needs frida on the device and ssh over usb
iproxy 2222 22 &
python3 dump.py -H 127.0.0.1 -p 2222 -u root -P alpine com.ctf.app

# option 2: on-device tools
#   ssh to the device, then:
#     flexdecrypt /var/containers/Bundle/Application/<UUID>/Foo.app/Foo
#     bagbak com.ctf.app

# verify the result: cryptid must now be 0
otool -l Foo.decrypted | grep -A4 LC_ENCRYPTION_INFO
```

### Parsing Mach-O and plists yourself

```python
#!/usr/bin/env python3
"""macho_info.py - print Mach-O architecture, load commands, cryptid and linked dylibs.

Pure stdlib: handles fat binaries and 64-bit Mach-O.

Usage: python3 macho_info.py Payload/Foo.app/Foo
"""
from __future__ import annotations

import plistlib
import struct
import sys

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1D
LC_MAIN = 0x80000028
LC_RPATH = 0x8000001C

CPU = {0x0100000C: "arm64", 0x0C: "arm", 0x01000007: "x86_64", 0x07: "i386"}


def slices(data: bytes) -> list[tuple[str, int, int]]:
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        n = struct.unpack(">I", data[4:8])[0]
        out = []
        for i in range(n):
            off = 8 + i * 20
            cputype, _sub, offset, size, _align = struct.unpack(">5I", data[off:off + 20])
            out.append((CPU.get(cputype, hex(cputype)), offset, size))
        return out
    return [("thin", 0, len(data))]


def parse_slice(data: bytes, base: int) -> dict:
    magic = struct.unpack("<I", data[base:base + 4])[0]
    if magic not in (MH_MAGIC_64, MH_CIGAM_64):
        return {"error": f"unsupported magic {magic:#x}"}
    cputype, _sub, _ft, ncmds, _sz, _fl, _res = struct.unpack("<7I", data[base + 4:base + 32])
    info: dict = {"arch": CPU.get(cputype, hex(cputype)), "ncmds": ncmds,
                  "dylibs": [], "segments": [], "cryptid": None, "signed": False, "rpaths": []}
    off = base + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[off:off + 8])
        if cmdsize == 0:
            break
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].rstrip(b"\x00").decode("ascii", "replace")
            vmaddr, vmsize = struct.unpack("<QQ", data[off + 24:off + 40])
            info["segments"].append((name, vmaddr, vmsize))
        elif cmd == LC_LOAD_DYLIB:
            nameoff = struct.unpack("<I", data[off + 8:off + 12])[0]
            s = data[off + nameoff:off + cmdsize].split(b"\x00")[0]
            info["dylibs"].append(s.decode("utf-8", "replace"))
        elif cmd == LC_RPATH:
            nameoff = struct.unpack("<I", data[off + 8:off + 12])[0]
            s = data[off + nameoff:off + cmdsize].split(b"\x00")[0]
            info["rpaths"].append(s.decode("utf-8", "replace"))
        elif cmd == LC_ENCRYPTION_INFO_64:
            cryptoff, cryptsize, cryptid = struct.unpack("<III", data[off + 8:off + 20])
            info["cryptid"] = cryptid
            info["cryptoff"] = cryptoff
            info["cryptsize"] = cryptsize
        elif cmd == LC_CODE_SIGNATURE:
            info["signed"] = True
        off += cmdsize
    return info


def read_plist(path: str) -> dict:
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    with open(argv[1], "rb") as fh:
        data = fh.read()
    for arch, off, size in slices(data):
        print(f"== slice {arch} offset={off} size={size}")
        info = parse_slice(data, off)
        if "error" in info:
            print("   " + info["error"])
            continue
        print(f"   arch={info['arch']} cmds={info['ncmds']} signed={info['signed']}")
        if info["cryptid"] is not None:
            state = "ENCRYPTED (dump from device first)" if info["cryptid"] else "decrypted"
            print(f"   cryptid={info['cryptid']} -> {state} "
                  f"off={info.get('cryptoff')} size={info.get('cryptsize')}")
        for name, addr, vmsize in info["segments"]:
            print(f"   segment {name:<16} vmaddr={addr:#x} vmsize={vmsize:#x}")
        for d in info["dylibs"]:
            print(f"   dylib  {d}")
        for r in info["rpaths"]:
            print(f"   rpath  {r}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # a minimal 64-bit mach-o header (32 bytes) + one LC_ENCRYPTION_INFO_64 command
        header = struct.pack("<8I", MH_MAGIC_64, 0x0100000C, 0, 2, 1, 0x14, 0, 0)
        lc = struct.pack("<5I", LC_ENCRYPTION_INFO_64, 20, 0x4000, 0x8000, 1)
        blob = header + lc
        info = parse_slice(blob, 0)
        assert info["arch"] == "arm64", info
        assert info["cryptid"] == 1, info
        assert info["cryptsize"] == 0x8000, info
        pl = plistlib.dumps({"CFBundleIdentifier": "com.ctf.app",
                             "CFBundleURLTypes": [{"CFBundleURLSchemes": ["ctfapp"]}]},
                            fmt=plistlib.FMT_BINARY)
        back = plistlib.loads(pl)
        assert back["CFBundleIdentifier"] == "com.ctf.app"
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Plists, assets and the keychain

```bash
# binary plist -> readable xml (in place, or to stdout)
plutil -convert xml1 Info.plist -o Info.xml
plutil -p Info.plist                       # pretty print without converting
plutil -extract CFBundleURLTypes xml1 -o - Info.plist

# every plist in the bundle at once
find Payload -name '*.plist' -exec sh -c 'echo "== $1"; plutil -p "$1"' _ {} \;

# NSUserDefaults on a device lives here
#   /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/<bundleid>.plist

# asset catalog
assetutil --info Payload/Foo.app/Assets.car | head -40

# compiled nib/storyboard back to readable xml
ibtool --convert-to-xib Main.storyboardc/Main.nib --output-format xml1 out.xib

# code signing details and the team identifier
codesign -dv --verbose=4 Payload/Foo.app
codesign -d --entitlements :- Payload/Foo.app

# keychain access groups tell you what the app can share
codesign -d --entitlements :- Payload/Foo.app | grep -A5 keychain-access-groups

# on a jailbroken device, dump the keychain items the app can see
objection --gadget com.ctf.app explore -s "ios keychain dump"
```

## Variants & pitfalls

- **Everything looks like garbage** -> `cryptid 1`. Nothing static will work until you
  dump a decrypted copy.
- **`class-dump` outputs nothing** -> a pure-Swift app, or the binary is still encrypted.
  Use `nm` + `swift demangle`, and let Ghidra's Swift metadata analysis run.
- **Fat binary confuses tools** -> `lipo -thin arm64` first. `arm64e` slices
  (pointer authentication) sometimes need `-arch arm64e` explicitly.
- **`otool` is macOS-only.** On Linux use `llvm-otool`, `llvm-objdump -macho`, or
  `ghidra`; `plistlib` in Python replaces `plutil`.
- **Signature breaks on any edit** - patching an iOS binary requires re-signing with
  `codesign -f -s <identity> --entitlements ent.plist` and a matching provisioning profile.
- **`Info.plist` `NSAllowsArbitraryLoads`** tells you ATS is off, which usually means the
  app will talk to your proxy happily.

## Tools

- `class-dump` / `class-dump-dyld` - Objective-C header reconstruction.
- `otool`, `nm`, `lipo`, `codesign`, `plutil`, `assetutil`, `ibtool` - Apple toolchain.
- `ghidra` (Mach-O + Objective-C analyser) or `hopper`.
- `frida-ios-dump`, `bagbak`, `flexdecrypt` - FairPlay decryption.
- `swift demangle` (part of the Swift toolchain) - Swift symbol names.
- `objection` - keychain and plist dumping on a live device.

## References

- Apple developer documentation: bundle structure, `Info.plist` keys, App Transport Security.
- Apple documentation on Keychain Services accessibility constants.
- Mach-O file format reference (load commands, `LC_ENCRYPTION_INFO_64`).
