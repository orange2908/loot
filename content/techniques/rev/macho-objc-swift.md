---
title: "Mach-O, Objective-C and Swift - macOS and iOS Reversing"
category: rev
subcategory: macho
type: technique
tags: [macho, macos, ios, objective-c, swift, objc-msgsend, class-dump, otool, lipo, codesign, lldb, dyld-shared-cache, demangling, load-commands, entitlements, frida, hopper, ghidra]
difficulty: medium
summary: "Thin the fat binary, read the Objective-C metadata for free class and method names, resolve objc_msgSend selectors, and demangle Swift symbols."
when_to_use:
  - "The challenge is a Mach-O binary, a .app bundle, an .ipa or a dylib"
  - "Ghidra shows objc_msgSend everywhere and no useful call graph"
  - "Symbols look like $s4main5CheckV6verifyyS2SF"
  - "You need to patch a macOS binary and it stops running afterwards"
tools: [otool, nm, lipo, codesign, class-dump, lldb, ghidra, hopper, frida, jtool2]
related: [cpp-vtables-stl, rust-binaries, windows-pe-reversing, triage-unknown-binary, binary-patching, dynamic-analysis-ltrace-ldpreload]
---

## TL;DR

Mach-O keeps a lot of metadata. Objective-C binaries hand you every class name, method name
and instance variable for free (`class-dump`), so the only real work is following
`objc_msgSend` dispatch. Swift is worse: names are mangled but demangleable, and the
decompiler output is noisy because of ARC and value witness calls.

## Recognise it and triage

```sh
file chall                       # Mach-O 64-bit executable arm64 / x86_64 / universal
# Universal ("fat") binary: pick one slice before doing anything else
lipo -info chall
lipo -thin arm64 chall -output chall.arm64
lipo -thin x86_64 chall -output chall.x86_64

otool -h chall.arm64             # header: cputype, filetype, ncmds, flags
otool -l chall.arm64 | less      # ALL load commands - the map of the file
otool -L chall.arm64             # linked dylibs (what the program can call)
otool -tV chall.arm64 | less     # disassembly with symbol names
nm -m chall.arm64                # symbols with their section/attributes
vtool -show chall.arm64          # build version / min OS / SDK
codesign -dvvv chall.arm64       # signing identity, team id, CDHash
codesign -d --entitlements - chall.arm64    # entitlements (iOS: what the app may do)
```

### Load commands worth knowing

| Load command | Meaning |
|---|---|
| `LC_SEGMENT_64` | a segment (`__TEXT`, `__DATA`, `__DATA_CONST`, `__LINKEDIT`) with its sections |
| `LC_MAIN` | entry point as a file offset (modern replacement for `LC_UNIXTHREAD`) |
| `LC_LOAD_DYLIB` | a linked library plus its compatibility version |
| `LC_LOAD_DYLINKER` | `/usr/lib/dyld` |
| `LC_ID_DYLIB` | present only in a dylib: its install name |
| `LC_RPATH` | runtime search path (`@executable_path/../Frameworks`) |
| `LC_CODE_SIGNATURE` | the signature blob in `__LINKEDIT` |
| `LC_ENCRYPTION_INFO_64` | **iOS FairPlay**: `cryptid=1` means `__TEXT` is encrypted on disk |
| `LC_FUNCTION_STARTS` | ULEB-encoded function boundaries - free function list |
| `LC_DYLD_INFO_ONLY` / `LC_DYLD_CHAINED_FIXUPS` | rebase/bind opcodes (imports) |
| `LC_UUID` | build identity, matches the dSYM |
| `LC_BUILD_VERSION` | platform (macOS/iOS/simulator) and SDK |

`cryptid=1` means you cannot statically analyse `__TEXT` from the App Store binary - you
must dump the decrypted image from a jailbroken device (`frida-ios-dump`, `bfdecrypt`,
`Clutch`) first.

### Sections that matter

```sh
otool -s __TEXT __cstring chall | head          # C string literals
otool -s __TEXT __objc_methname chall | head    # every selector name
otool -s __DATA __objc_classlist chall          # pointers to class_t structures
otool -s __TEXT __swift5_types chall            # Swift type metadata
otool -s __TEXT __unwind_info chall             # function boundaries fallback
```

| Section | Contents |
|---|---|
| `__TEXT,__text` | code |
| `__TEXT,__cstring` | C literals |
| `__TEXT,__objc_methname` | selector strings (one NUL-separated blob) |
| `__TEXT,__objc_classname` | class name strings |
| `__TEXT,__objc_methtype` | method type encodings (`v24@0:8@16`) |
| `__DATA,__objc_classlist` | pointers to `class_t` |
| `__DATA,__objc_const` | `class_ro_t` structures (name, methods, ivars, protocols) |
| `__DATA,__objc_selrefs` | selector references - the xrefs you need |
| `__DATA,__objc_data` | the class objects themselves |
| `__DATA,__cfstring` | `CFStringRef` literals (`@"..."` in ObjC source) |
| `__TEXT,__swift5_types`, `__swift5_proto`, `__swift5_fieldmd` | Swift metadata |

## Code - parse a Mach-O without any tooling

```python
#!/usr/bin/env python3
"""machodump.py - load commands, segments/sections, dylibs and ObjC selectors.

Handles fat (universal) and thin, 32- and 64-bit, both endiannesses. Pure stdlib.

Usage:
    python3 machodump.py ./chall
    python3 machodump.py ./chall --selectors
"""
import struct
import sys

FAT_MAGIC = 0xCAFEBABE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC_32 = 0xFEEDFACE
MH_CIGAM_32 = 0xCEFAEDFE

CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
       0x0200000C: "arm64_32", 18: "ppc"}
FILETYPE = {1: "object", 2: "execute", 6: "dylib", 8: "bundle", 10: "dsym"}
LC = {
    0x01: "LC_SEGMENT", 0x02: "LC_SYMTAB", 0x0B: "LC_DYSYMTAB", 0x0C: "LC_LOAD_DYLIB",
    0x0D: "LC_ID_DYLIB", 0x0E: "LC_LOAD_DYLINKER", 0x19: "LC_SEGMENT_64",
    0x1B: "LC_UUID", 0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE",
    0x21: "LC_ENCRYPTION_INFO", 0x22: "LC_DYLD_INFO", 0x26: "LC_FUNCTION_STARTS",
    0x2A: "LC_SOURCE_VERSION", 0x2B: "LC_DYLD_ENVIRONMENT",
    0x2C: "LC_ENCRYPTION_INFO_64", 0x32: "LC_BUILD_VERSION",
    0x80000022: "LC_DYLD_INFO_ONLY", 0x80000028: "LC_MAIN",
    0x80000033: "LC_DYLD_EXPORTS_TRIE", 0x80000034: "LC_DYLD_CHAINED_FIXUPS",
}


def slices(data: bytes) -> list[tuple[int, int]]:
    """Return [(offset, size)] for each architecture in the file."""
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, 0xBEBAFECA):
        nfat = struct.unpack_from(">I", data, 4)[0]
        out = []
        for i in range(nfat):
            cpu, _sub, off, size, _align = struct.unpack_from(">IIIII", data, 8 + i * 20)
            print(f"[*] fat slice {i}: {CPU.get(cpu, hex(cpu))} at {off:#x} ({size} bytes)")
            out.append((off, size))
        return out
    return [(0, len(data))]


def parse_slice(data: bytes, base: int, show_sel: bool) -> None:
    magic = struct.unpack_from("<I", data, base)[0]
    if magic in (MH_MAGIC_64, MH_CIGAM_64):
        endian = "<" if magic == MH_MAGIC_64 else ">"
        is64 = True
    elif magic in (MH_MAGIC_32, MH_CIGAM_32):
        endian = "<" if magic == MH_MAGIC_32 else ">"
        is64 = False
    else:
        print(f"[-] not a Mach-O slice at {base:#x} (magic {magic:#x})")
        return

    cpu, _sub, ftype, ncmds, _sizeofcmds, flags = struct.unpack_from(
        endian + "IIIIII", data, base + 4)
    print(f"[*] {CPU.get(cpu, hex(cpu))} {FILETYPE.get(ftype, ftype)}, "
          f"{ncmds} load commands, flags={flags:#x}")
    if flags & 0x200000:
        print("    PIE")

    off = base + (32 if is64 else 28)
    sections: list[dict] = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        name = LC.get(cmd, f"{cmd:#x}")

        if cmd in (0x19, 0x01):                       # LC_SEGMENT(_64)
            segname = data[off + 8:off + 24].rstrip(b"\0").decode(errors="replace")
            if cmd == 0x19:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    endian + "QQQQ", data, off + 24)
                nsects = struct.unpack_from(endian + "I", data, off + 64)[0]
                sec_off = off + 72
                sec_size = 80
            else:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    endian + "IIII", data, off + 24)
                nsects = struct.unpack_from(endian + "I", data, off + 48)[0]
                sec_off = off + 56
                sec_size = 68
            print(f"    {name} {segname:<12} vm={vmaddr:#012x} size={vmsize:#x} "
                  f"file={fileoff:#x}")
            for i in range(nsects):
                sbase = sec_off + i * sec_size
                sname = data[sbase:sbase + 16].rstrip(b"\0").decode(errors="replace")
                sseg = data[sbase + 16:sbase + 32].rstrip(b"\0").decode(errors="replace")
                if cmd == 0x19:
                    saddr, ssize = struct.unpack_from(endian + "QQ", data, sbase + 32)
                    soff = struct.unpack_from(endian + "I", data, sbase + 48)[0]
                else:
                    saddr, ssize = struct.unpack_from(endian + "II", data, sbase + 32)
                    soff = struct.unpack_from(endian + "I", data, sbase + 40)[0]
                sections.append({"seg": sseg, "name": sname, "addr": saddr,
                                 "size": ssize, "off": soff})
                print(f"        {sseg},{sname:<18} addr={saddr:#012x} size={ssize:#x}")

        elif cmd in (0x0C, 0x0D, 0x18):               # LC_LOAD_DYLIB / ID / WEAK
            name_off = struct.unpack_from(endian + "I", data, off + 8)[0]
            start = off + name_off
            end = data.index(b"\0", start)
            print(f"    {name} {data[start:end].decode(errors='replace')}")

        elif cmd == 0x80000028:                        # LC_MAIN
            entryoff, _stack = struct.unpack_from(endian + "QQ", data, off + 8)
            print(f"    LC_MAIN entryoff={entryoff:#x}")

        elif cmd in (0x21, 0x2C):                      # LC_ENCRYPTION_INFO(_64)
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", data, off + 8)
            print(f"    {name} cryptid={cryptid} off={cryptoff:#x} size={cryptsize:#x}")
            if cryptid:
                print("    [!] __TEXT is FairPlay-encrypted; dump from a device first")

        elif cmd == 0x1D:
            print(f"    {name} (code signature present)")
        else:
            print(f"    {name}")
        off += cmdsize

    if show_sel:
        for sec in sections:
            if sec["name"] in ("__objc_methname", "__objc_classname", "__cstring"):
                blob = data[base + sec["off"]:base + sec["off"] + sec["size"]]
                print(f"\n[*] {sec['seg']},{sec['name']} ({sec['size']} bytes)")
                addr = sec["addr"]
                for piece in blob.split(b"\x00"):
                    if piece:
                        print(f"    {addr:#012x}  {piece.decode(errors='replace')}")
                    addr += len(piece) + 1


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: machodump.py <binary> [--selectors]")
        return 1
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
    for off, _size in slices(data):
        parse_slice(data, off, "--selectors" in sys.argv)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Objective-C

Every ObjC class carries a `class_ro_t` with its name, method list (selector, type encoding,
implementation pointer) and instance variables. `class-dump` turns that back into headers:

```sh
class-dump chall > chall.h            # every @interface, method signature and ivar
class-dump -H -o headers/ chall       # one header per class
# For a .app bundle:
class-dump /Applications/Chall.app/Contents/MacOS/Chall
```

That output is a map of the program. Find the suspicious method
(`- (BOOL)validateFlag:(NSString *)arg1;`), then go to its implementation in Ghidra.

### objc_msgSend dispatch

ObjC calls are not direct calls. `[obj checkFlag:s]` compiles to:

```
; arm64
ldr  x0, [x19]                  ; receiver
adrp x1, #0x100008000
ldr  x1, [x1, #0x210]           ; selector from __objc_selrefs -> "checkFlag:"
mov  x2, x20                    ; first argument
bl   _objc_msgSend
```

```
; x86-64
mov  rdi, [rbx]                 ; receiver (self)
mov  rsi, [rip + selRef]        ; selector (_cmd)
mov  rdx, r14                   ; first argument
call _objc_msgSend
```

So: **the second argument is always the selector**. To resolve a call target, read the
selector pointer's target string, then look up that selector in `class-dump` output for the
receiver's class. Ghidra's ObjC analyzer (`Analysis -> Objective-C 2 ...`) creates
`_objc_msgSend` call annotations and renames selector references; IDA does the same and can
be improved with the `ObjcHelper`/`objc2_analyzer` scripts. Hopper resolves them natively.

Because dispatch is dynamic, **static xrefs to a method's implementation are usually absent**
- search for the selector string instead, and cross-reference `__objc_selrefs`.

The type encoding string (`__objc_methtype`), e.g. `B24@0:8@16`, reads as: return `BOOL`,
total 24 bytes of arguments, `@` object at offset 0 (self), `:` selector at 8, `@` object at
16. Useful for recovering signatures Ghidra guessed wrong.

### Dynamic analysis

```sh
# Log every ObjC message the process sends (macOS, needs SIP considerations)
NSObjCMessageLoggingEnabled=YES ./chall        # writes /tmp/msgSends-<pid>
# Or use dtrace (requires disabling SIP for arbitrary processes)
sudo dtrace -n 'pid$target::objc_msgSend:entry { printf("%s", copyinstr(arg1)); }' -c ./chall
```

## Swift

Swift symbols are mangled and start with `$s` (Swift 5) or `_T0` (Swift 4):

```sh
# Demangle a single symbol
xcrun swift-demangle '$s4main5CheckV6verifyySbSSF'
swift demangle '$s4main5CheckV6verifyySbSSF'
# Demangle every symbol in a binary
nm chall | xcrun swift-demangle | less
# Ghidra: enable the Swift demangler in Analysis Options, or use a community script
```

Mangling cheat: `$s` prefix, then a length-prefixed module name (`4main`), a length-prefixed
type (`5Check`), a kind character (`V` struct, `C` class, `O` enum, `P` protocol), the
member name, then the function signature (`y` argument list start, `Sb` Bool, `SS` String,
`Si` Int, `F` function).

Practical differences from ObjC:

- Swift structs and enums have **no runtime metadata you can class-dump** in the ObjC sense;
  `__swift5_types` gives you nominal type descriptors that tools can parse, but the output
  is far less complete.
- Method dispatch is **static or vtable-based**, not `objc_msgSend`, unless the class is
  `@objc`/`NSObject`-derived. That is good for xrefs, bad for names.
- `String` is not a C string: it is a 16-byte struct with small-string optimisation (up to
  15 UTF-8 bytes inline, tagged) or a pointer to a `__StringStorage` object. Do not expect
  `strings` to show you a flag that lives in a small Swift `String` literal built at runtime.
- ARC inserts `swift_retain`/`swift_release` everywhere; the decompiler output is noisy.
  Mentally delete those calls.
- Bounds checks call `Swift runtime failure: Index out of range` - like Rust, these mark
  array accesses and are handy landmarks.

## Debugging with lldb

```
# Start
lldb ./chall
(lldb) settings set target.env-vars DYLD_INSERT_LIBRARIES=./hook.dylib
(lldb) process launch --stop-at-entry
(lldb) r arg1

# Breakpoints
(lldb) b main                        # by symbol
(lldb) b -n validateFlag             # by name, any module
(lldb) br set -a 0x100003f40         # by address
(lldb) br set -r 'check.*'           # regex over symbol names
(lldb) br set -F '-[Checker validateFlag:]'    # full ObjC method name
(lldb) br set -S validateFlag:       # by selector

# Inspection
(lldb) image list                    # modules and their load addresses (ASLR slide!)
(lldb) image lookup -a 0x100003f40   # what is at this address
(lldb) register read                 # all registers
(lldb) x/32xb $x0                    # hexdump 32 bytes at x0
(lldb) x/s $x1                       # the selector string in an objc_msgSend call
(lldb) po $x0                        # print an ObjC object description
(lldb) expr (int)strlen((char*)$x0)  # call functions in the target
(lldb) memory write 0x100008000 0x01 # patch memory live
(lldb) dis -n validateFlag           # disassemble a function
(lldb) thread step-inst              # single step
```

`image list` gives the **slide**: your static address from Ghidra plus the slide equals the
runtime address. Ghidra usually bases Mach-O at `0x100000000`, which matches the file's
`__TEXT` vmaddr, so the slide is `runtime_base - 0x100000000`.

## Patching and code signing

```sh
# Patch bytes as usual (see binary-patching), then RE-SIGN or macOS kills the process
codesign -f -s - ./chall                 # ad-hoc signature
codesign -f -s - --deep ./Chall.app      # whole bundle
codesign -dvvv ./chall                   # verify
# If the binary has the hardened runtime and you need library injection:
codesign -f -s - --options runtime --entitlements ent.plist ./chall
# Remove the quarantine attribute for downloaded files
xattr -dr com.apple.quarantine ./Chall.app
```

Injection with `DYLD_INSERT_LIBRARIES` (the macOS `LD_PRELOAD`) only works if the target is
**not** hardened/restricted and SIP is not blocking it - Apple-signed binaries and hardened
apps ignore it. For those, use Frida or re-sign the binary yourself with an ad-hoc signature
after stripping the hardened flag.

```sh
# Frida on macOS / jailbroken iOS
frida-ps -Ua                                  # list apps on a USB device
frida -U -f com.example.chall -l hook.js --no-pause
frida-trace -U -f ./chall -m '-[Checker validateFlag:]'
```

## dyld shared cache

System libraries no longer exist as standalone files on macOS 11+/iOS: they live in
`/System/Library/dyld/dyld_shared_cache_arm64e` (or under
`/System/Volumes/Preboot/Cryptexes/OS/`). To analyse one, extract it first with
`dyld-shared-cache-extractor`, `ipsw dyld extract`, or `jtool2 -e`. `dyld_info -exports`
also queries the cache directly.

## Variants & pitfalls

- **Analysing the fat binary directly** confuses many tools. Always `lipo -thin` first.
- **arm64e** (pointer authentication) inserts `pac*`/`aut*` instructions and signed
  pointers; Ghidra may show garbage for vtables. Use an arm64 slice when one exists.
- **Chained fixups** (`LC_DYLD_CHAINED_FIXUPS`, macOS 12+) replace classic bind opcodes;
  older tools show unresolved imports. Update Ghidra/IDA.
- **`cryptid=1`** on App Store iOS binaries: static analysis is impossible until you dump
  from a device.
- **`__cfstring` vs `__cstring`**: an ObjC `@"literal"` is a 32-byte CFString struct whose
  second-to-last field points at the actual bytes in `__cstring`. Follow the pointer.
- **Swift `String` interpolation** builds strings at runtime - grep will not find them.
- **Entitlements are data**: `codesign -d --entitlements -` sometimes reveals exactly what a
  challenge expects (a keychain group, a special file path).
- **Notarisation/Gatekeeper** blocks unsigned downloaded binaries; `xattr -dr
  com.apple.quarantine` fixes the CTF case.

## Tools

- `otool`, `nm`, `lipo`, `vtool`, `codesign`, `dyld_info` - ship with the Xcode CLI tools.
- `class-dump` - ObjC headers from the metadata.
- `jtool2` - a swiss-army replacement for otool with cache support.
- `Hopper` - best-in-class ObjC handling on macOS.
- `Ghidra` (with the ObjC and Swift analyzers) / `IDA` - free and full-featured.
- `lldb` - the system debugger; `br set -F` for ObjC methods.
- `frida` / `frida-ios-dump` - dynamic hooking and decrypted-binary dumps.
- `ipsw`, `dyld-shared-cache-extractor` - cache extraction.

## References

- Apple's `<mach-o/loader.h>` header: the load command constants and structure layouts used
  by the script above.
- Apple `man` pages: `otool(1)`, `lipo(1)`, `codesign(1)`, `nm(1)`.
- The Swift repository's `docs/ABI/Mangling.rst` for the symbol mangling grammar.
