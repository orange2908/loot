---
title: "Triage - First 10 Minutes With an Unknown Binary"
category: rev
subcategory: triage
type: technique
tags: [triage, file, strings, binwalk, checksec, readelf, ltrace, strace, entropy, packers, upx, golang, rust, pyinstaller, dotnet, nim, elf, pe, macho, toolchain-fingerprint]
difficulty: easy
summary: "A fixed 10-minute recon routine for any unknown binary: identify format, arch, toolchain, packing and the next technique file to open."
when_to_use:
  - "You just downloaded a rev challenge and have no idea what it is"
  - "The decompiler output looks insane and you suspect packing or a non-C toolchain"
  - "You need to decide between Ghidra, angr, a .NET decompiler or an unpacker before wasting an hour"
  - "`file` says 'ELF 64-bit LSB executable' and nothing else is obvious"
tools: [file, strings, binwalk, checksec, pwntools, readelf, objdump, nm, ltrace, strace, ent, python]
related: [ghidra-workflow, ida-r2-binja-workflow, dynamic-analysis-ltrace-ldpreload, packers-and-unpacking, go-binaries, rust-binaries, dotnet-reversing, python-bytecode-pyinstaller, windows-pe-reversing, macho-objc-swift, firmware-raw-blob-loading]
---

## TL;DR

Never open a decompiler first. Spend ten minutes on a fixed checklist - format,
architecture, linkage, toolchain, entropy, imports, one traced run - and it
tells you which technique file to open next. Ninety percent of CTF rev
challenges are classified by `file`, `strings -el`, `checksec` and one `ltrace`.

## Recognise it

Signals you are still in triage territory (do not start reversing yet):

- `file` ends with `stripped` and nothing else useful.
- Ghidra's function list has three functions, one of them 400 KB.
- `strings` is almost empty, or the binary is 98% high-entropy bytes, or the
  entry point jumps into a blob that writes to its own `.text`.
- The import table has only `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`.
- The file is 4 MB for a program that prints "Enter the flag:".

Each is a *routing signal*, not a challenge. Route first.

## Theory - what the checklist actually measures

Five independent questions, in this order:

1. **Container** - ELF / PE / Mach-O / raw blob / archive / installer. A wrong
   guess makes every later tool print garbage.
2. **Architecture and endianness** - x86-64, i386, ARM (32/64), MIPS (be/le),
   RISC-V. Picks the disassembler backend and whether you need `qemu-<arch>`.
3. **Toolchain / source language** - C, C++, Go, Rust, .NET, Nim, frozen Python,
   Java. Decides the *entire* rest of your approach: Go wants `GoReSym` and
   string-slice awareness, .NET wants `dnSpy` and no disassembler at all.
4. **Transformation** - packed, obfuscated, self-modifying, static, stripped.
   Decides whether you must unpack before anything else works.
5. **Behaviour class** - stdin, file, socket, `ptrace`, fork? One `strace` run.

Entropy is the cheapest proxy for question 4: x86 code sits at 6.0-6.6
bits/byte, English at 4.0-5.0, compressed/encrypted at 7.8-8.0. A `.text` at 7.9
is packed; a `.rodata` at 7.9 is an embedded blob to carve.

## Workflow

```sh
# --- Step 0: never run it yet; keep a pristine copy and hash it ---
cp ./chall ./chall.orig && chmod -w ./chall.orig   # you WILL patch the working one
sha256sum ./chall            # prove in your notes which build you analysed
# --- Step 1: container, arch, linkage. DYN + INTERP = PIE; EXEC without
#     INTERP = static; no .dynamic at all = fully static, libc inlined, no PLT
file ./chall                 # format, arch, endianness, linkage, interp, stripped
lipo -info ./chall 2>/dev/null   # macOS: list the slices of a fat Mach-O
readelf -h ./chall           # class, data (LSB/MSB), type, machine, entry
readelf -d ./chall           # NEEDED libs, RPATH/RUNPATH, SONAME, INIT_ARRAY
readelf -S -W ./chall        # section sizes/flags: huge .rodata? missing .text?
readelf -l -W ./chall        # program headers; an RWX segment is a packer smell
# --- Step 2: mitigations. In rev only PIE (your notes hold offsets, not
#     addresses) and Partial RELRO (GOT is a viable patch point) really matter
checksec --file=./chall      # canary / NX / PIE / RELRO / fortify / RUNPATH
python3 -c "from pwn import ELF; e=ELF('./chall'); print(e.checksec())"
# --- Step 3: strings, three passes. -a scans the WHOLE file (GNU strings does
#     loadable sections only for ELF); -t x gives the hex offset to seek to ---
strings -a -t x -n 6 ./chall | less
strings -a -el -n 6 ./chall  # UTF-16LE: mandatory for PE, or you see nothing
objdump -s -j .rodata ./chall | head -60      # only the section that holds text
strings -a ./chall | grep -Ei 'flag|ctf\{|password|secret|key|correct|wrong|nope'
# --- Step 4: symbols and imports ---
nm -D --defined-only ./chall # .dynsym survives `strip`
nm -D -u ./chall             # undefined = what it imports from libc
nm -C ./chall | head -40     # full symtab; says "no symbols" when stripped
objdump -d -j .plt ./chall | grep '@plt'      # libc calls reachable at runtime
python3 -c "import pefile,sys; p=pefile.PE(sys.argv[1]); p.print_info()" chall.exe
```

The import list is a behaviour fingerprint:

| Imports you see | What it means |
| --- | --- |
| `ptrace`, `personality`, `prctl` | anti-debug -> `anti-debug-bypass` |
| `VirtualAlloc` + `GetProcAddress` only | packer/loader stub |
| `mmap` + `mprotect` RWX | self-modifying or JIT/VM |
| `BCryptDecrypt`, `EVP_*`, `AES_*` | crypto check, pull the key at runtime |
| `__isoc99_scanf`, `fgets`, `read` | classic stdin flag checker |
| `fork`, `wait4`, `PTRACE_TRACEME` | self-tracing anti-debug |
| `gettimeofday`, `clock_gettime` | timing anti-debug or a side channel |

```sh
# --- Step 5: embedded files and blobs. A PyInstaller EXE, a UPX-SFX, a
#     firmware image and a Go binary with an appended zip all show up here ---
binwalk ./chall              # scan for zip/gzip/PNG/ELF-in-ELF/squashfs magic
binwalk -eM --run-as=root ./chall   # extract to _chall.extracted/, -M recurses
binwalk -E ./chall           # text entropy plot; a rising edge = compressed blob
# --- Step 6: entropy ---
ent ./chall                  # whole-file entropy + chi-square (package: ent)
python3 triage.py ./chall    # per-section, which is far more useful
# --- Step 7: one traced run, in a throwaway container/VM ---
ltrace -S -f ./chall         # library calls (+ syscalls), following children
strace -f -e trace=openat,read,write,ptrace,execve,mmap,mprotect ./chall
echo 'AAAABBBBCCCCDDDD' | ltrace -e 'str*+mem*' ./chall   # marker input
# strcmp("AAAABBBBCCCCDDDD", "real_flag") -> dynamic-analysis-ltrace-ldpreload
# --- Step 8: peek at the code without a full analysis ---
readelf -h ./chall | grep Entry
objdump -d --start-address=0x1140 --stop-address=0x1240 -M intel ./chall
objdump -d -M intel --disassemble='main' ./chall
objdump -D -b binary -m i386:x86-64 -M intel blob.bin | head -80   # raw blob
```

## Detecting the toolchain from strings

The highest-leverage classification: the first pattern that hits picks your file.

```sh
strings -a ./chall | grep -m5 -E 'go1\.[0-9]+|runtime\.gopanic|Go buildinf:|rustc|/rustc/[0-9a-f]{40}|core::panicking|cargo/registry|_ZN|_ZSt|libstdc\+\+|__cxa_throw|libc\+\+abi|nimFrame|NimMainModule|@mmain\.nim|system\.nim'
strings -a ./chall.exe | grep -m5 -E 'mscoree\.dll|_CorExeMain|#Strings|#Blob|BSJB'
strings -a ./chall | grep -m5 -E 'PyInstaller|pyi-|MEIPASS|python3[0-9]\.dll|zipimport'
strings -a ./chall | grep -m3 -E 'UPX!|\$Info: This file is packed'
go version ./chall           # works on any Go binary, even stripped
upx -t ./chall && upx -d -o chall.unpacked ./chall
xxd -l 4 ./chall | grep -i 'cafe babe'        # Java .class (or fat Mach-O)
```

- **Go buildinfo**: the magic `\xff Go buildinf:` in `.go.buildinfo` encodes the
  Go version and, for module builds, the dependency list (`go version -m`).
- **Rust**: the 40-hex `/rustc/<commit>/library/core/src/...` panic locations
  survive stripping, because panic messages are `&'static str`.
- **.NET vs native PE**: a managed PE has data directory 14
  (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`) non-zero and a `BSJB` metadata root.
  Do not disassemble it - use `ilspycmd`, `dnSpy` or `dotPeek`.
- **Nim**: mangles names as `name_<hash>`, always references `nimFrame` and
  `NimMainModule`; decompiles like the ugly C it is.
- **PyInstaller**: `MEI` cookie near EOF; `pyinstxtractor.py`, then decompile
  the `.pyc` files.

## Code

```python
#!/usr/bin/env python3
"""triage.py - first-look classifier for an unknown binary.
Usage: python3 triage.py ./chall   (or --selftest). Prints container, arch,
entry, per-section entropy (>= 7.2 = probably packed), high-entropy ranges to
carve, a toolchain guess and suspicious imports. Pure stdlib, no pefile.
"""
import math, re, struct, sys
from collections import Counter

PACKED_ENTROPY = 7.2      # bits/byte above which a section looks compressed
TEXTY_ENTROPY = 5.2       # below this a section is mostly ASCII strings
ELF_MACHINE = {0x02: "SPARC", 0x03: "x86 (i386)", 0x08: "MIPS",
               0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390",
               0x28: "ARM (32-bit)", 0x2A: "SuperH", 0x32: "IA-64",
               0x3E: "x86-64", 0xB7: "AArch64 (ARM64)", 0xF3: "RISC-V"}
ELF_TYPE = {1: "REL (object)", 2: "EXEC (non-PIE)", 3: "DYN (PIE or .so)",
            4: "CORE"}
PE_MACHINE = {0x014C: "x86 (i386)", 0x0200: "IA-64", 0x8664: "x86-64",
              0x01C0: "ARM", 0xAA64: "AArch64 (ARM64)",
              0x01C4: "ARMv7 (Thumb-2)"}
MACHO_CPU = {7: "x86 (i386)", 0x01000007: "x86-64", 12: "ARM",
             0x0100000C: "AArch64 (ARM64)"}
SUSPICIOUS_IMPORTS = {                       # name -> why you care
    "ptrace": "anti-debug (PTRACE_TRACEME self-attach)",
    "personality": "anti-debug (ADDR_NO_RANDOMIZE)", "prctl": "anti-debug",
    "IsDebuggerPresent": "anti-debug (PEB BeingDebugged)",
    "CheckRemoteDebuggerPresent": "anti-debug (Win32)",
    "NtQueryInformationProcess": "anti-debug (ProcessDebugPort)",
    "signal": "SIGTRAP anti-debug / exception-driven control flow",
    "sigaction": "SIGTRAP/SIGSEGV obfuscation", "rdtsc": "timing check",
    "clock_gettime": "timing or side channel", "mprotect": "self-modifying code",
    "VirtualAlloc": "unpacking / shellcode loader", "VirtualProtect": "RWX flip",
    "GetProcAddress": "dynamic import resolution (packer/obfuscator)",
    "LoadLibraryA": "dynamic import resolution", "dlopen": "late-bound payload",
    "dlsym": "late-bound symbol resolution", "execve": "process replacement",
    "fork": "self-tracing / child-does-the-work", "system": "shells out",
    "memfd_create": "fileless payload execution",
}
LANGUAGE_SIGNS = [                           # (regex, language, note)
    (rb"\xff Go buildinf:", "Go", "buildinfo magic; run `go version -m`"),
    (rb"runtime\.gopanic|runtime\.morestack|go\.buildid", "Go", "Go runtime"),
    (rb"/rustc/[0-9a-f]{40}/library", "Rust", "rustc panic source paths"),
    (rb"core::panicking|RUST_BACKTRACE|cargo/registry", "Rust", "panic paths"),
    (rb"nimFrame|NimMainModule|nimCopyMem", "Nim", "Nim runtime helpers"),
    (rb"BSJB|mscoree\.dll|_CorExeMain", ".NET", "CLR metadata/bootstrap"),
    (rb"PyInstaller|_MEIPASS|pyi_rth_", "Python (PyInstaller)", "pyinstxtractor"),
    (rb"Py_Initialize|python3\.[0-9]+|zipimport", "Python (embedded)", "frozen"),
    (rb"UPX!|UPX0|\$Info: This file is packed", "packed with UPX", "upx -d"),
    (rb"libstdc\+\+|__cxa_throw|_ZSt|_ZNSt", "C++ (libstdc++)", "nm -C"),
    (rb"libc\+\+abi|__cxa_allocate_exception", "C++ (libc++)", "LLVM C++ ABI"),
    (rb"\xca\xfe\xba\xbe", "Java class or Mach-O fat", "check first 4 bytes"),
    (rb"GCC: \(", "C (GCC)", "GCC-built"), (rb"clang version", "C/C++", "clang"),
]
def shannon(data):          # Shannon entropy in bits/byte, 0.0 when empty
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
def entropy_blocks(data, block=4096):   # [(offset, entropy)] per chunk
    return [(o, shannon(data[o:o + block])) for o in range(0, len(data), block)]
def hot_runs(blocks, threshold=PACKED_ENTROPY):   # merge hot blocks into runs
    runs, start, prev_end = [], None, 0
    for off, ent in blocks:
        if ent >= threshold:
            start = off if start is None else start
            prev_end = off + 4096
        elif start is not None:
            runs.append((start, prev_end))
            start = None
    return runs + [(start, prev_end)] if start is not None else runs
def parse_elf(data):        # header facts + [(section, file offset, size)]
    is64, little = data[4] == 2, data[5] == 1
    end = "<" if little else ">"
    etype, machine = struct.unpack_from(end + "HH", data, 16)
    entry, _ph, shoff = struct.unpack_from(end + ("QQQ" if is64 else "III"), data, 24)
    shentsize, shnum, shstrndx = struct.unpack_from(end+"HHH", data, 58 if is64 else 46)
    sections = []
    if shoff and shnum and shstrndx < shnum:
        hdr = shoff + shstrndx * shentsize
        fmt, at = (end + "QQ", hdr + 24) if is64 else (end + "II", hdr + 16)
        str_off, str_size = struct.unpack_from(fmt, data, at)
        strtab = data[str_off:str_off + str_size]
        for i in range(shnum):
            hdr = shoff + i * shentsize
            if hdr + shentsize > len(data):
                break
            name_idx, sh_type = struct.unpack_from(end + "II", data, hdr)
            fmt, at = (end + "QQ", hdr + 24) if is64 else (end + "II", hdr + 16)
            off, size = struct.unpack_from(fmt, data, at)
            name = strtab[name_idx:strtab.find(b"\x00", name_idx)]
            if sh_type != 8:          # skip SHT_NOBITS: .bss has no file bytes
                sections.append((name.decode("ascii", "replace") or "<%d>" % i,
                                 off, size))
    return {"format": "ELF%d %s" % (64 if is64 else 32, "LSB" if little else "MSB"),
            "arch": ELF_MACHINE.get(machine, "machine 0x%04x" % machine),
            "type": ELF_TYPE.get(etype, "type %d" % etype),
            "entry": entry, "sections": sections}
def parse_pe(data):         # data directory 14 non-zero => managed .NET
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine, nsec = struct.unpack_from("<HH", data, e_lfanew + 4)
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_off = e_lfanew + 24
    plus = struct.unpack_from("<H", data, opt_off)[0] == 0x20B
    entry = struct.unpack_from("<I", data, opt_off + 16)[0]
    dd_off = opt_off + (112 if plus else 96)      # data directories start here
    clr_rva = (struct.unpack_from("<I", data, dd_off + 14 * 8)[0]
               if dd_off + 15 * 8 <= len(data) else 0)
    sections = []
    for i in range(nsec):
        hdr = opt_off + opt_size + i * 40
        if hdr + 40 > len(data):
            break
        name = data[hdr:hdr + 8].rstrip(b"\x00").decode("ascii", "replace")
        _vsz, _vaddr, rsize, roff = struct.unpack_from("<IIII", data, hdr + 8)
        sections.append((name or "<%d>" % i, roff, rsize))
    return {"format": "PE32+" if plus else "PE32",
            "arch": PE_MACHINE.get(machine, "machine 0x%04x" % machine),
            "type": ".NET managed assembly" if clr_rva else "native",
            "entry": entry, "sections": sections}
def parse_macho(data):      # walks LC_SEGMENT/LC_SEGMENT_64 for sections
    magic = struct.unpack_from("<I", data, 0)[0]
    little = magic in (0xFEEDFACE, 0xFEEDFACF)
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    end = "<" if little else ">"
    cputype = struct.unpack_from(end + "i", data, 4)[0] & 0xFFFFFFFF
    ncmds = struct.unpack_from(end + "I", data, 16)[0]
    off, sections = (32 if is64 else 28), []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", data, off)
        if cmdsize == 0:
            break
        if cmd in (0x01, 0x19):                       # LC_SEGMENT / _64
            big = cmd == 0x19
            seg = data[off + 8:off + 24].rstrip(b"\x00").decode("ascii", "replace")
            nsects = struct.unpack_from(end + "I", data, off + (64 if big else 48))[0]
            s = off + (72 if big else 56)
            for _i in range(nsects):
                nm = data[s:s + 16].rstrip(b"\x00").decode("ascii", "replace")
                size = struct.unpack_from(end + ("Q" if big else "I"), data,
                                          s + (40 if big else 36))[0]
                foff = struct.unpack_from(end + "I", data, s + (48 if big else 40))[0]
                sections.append(("%s,%s" % (seg, nm), foff, size))
                s += 80 if big else 68
        off += cmdsize
    return {"format": "Mach-O %d-bit" % (64 if is64 else 32),
            "arch": MACHO_CPU.get(cputype, "cputype 0x%08x" % cputype),
            "type": "executable/dylib", "entry": 0, "sections": sections}
def identify(data):         # dispatch on magic; same dict shape every time
    if data[:4] == b"\x7fELF":
        return parse_elf(data)
    if data[:2] == b"MZ" and len(data) > 0x40:
        try:
            return parse_pe(data)
        except (struct.error, IndexError):
            pass
    if struct.unpack_from("<I", data, 0)[0] in (0xFEEDFACE, 0xFEEDFACF,
                                                0xCEFAEDFE, 0xCFFAEDFE):
        return parse_macho(data)
    flat = {"entry": 0, "sections": []}
    if data[:4] == b"\xca\xfe\xba\xbe":
        # Java .class and Mach-O fat share this magic: a fat header's next
        # dword is a small slice count, a class file's is major/minor version.
        nfat = struct.unpack_from(">I", data, 4)[0]
        if 1 <= nfat <= 32:
            return dict(flat, format="Mach-O fat, %d slices" % nfat,
                        arch="multiple - run `lipo -info`",
                        type="container: lipo -thin arm64 -output out in")
        return dict(flat, format="Java .class", arch="JVM", type="bytecode")
    if data[:2] == b"PK":
        return dict(flat, format="ZIP (jar/apk/docx/pyz?)", arch="n/a",
                    type="archive")
    return dict(flat, format="raw blob / unknown", arch="?", type="?")
def report(path):           # print the whole triage sheet for one file
    with open(path, "rb") as fh:
        data = fh.read()
    info = identify(data)
    print("file     : %s  (%d bytes)" % (path, len(data)))
    for key in ("format", "arch", "type"):
        print("%-9s: %s" % (key, info[key]))
    if info["entry"]:
        print("entry    : 0x%x" % info["entry"])
    print("overall  : entropy %.3f bits/byte" % shannon(data))
    print("sections (H >= %.1f is probably packed/encrypted):" % PACKED_ENTROPY)
    if not info["sections"]:
        print("  (none - raw blob or unsupported format)")
    for name, off, size in info["sections"]:
        if size == 0 or off + size > len(data):
            continue
        ent = shannon(data[off:off + size])
        tag = "  <== PACKED?" if ent >= PACKED_ENTROPY else (
            "  (text-like)" if ent <= TEXTY_ENTROPY and size > 256 else "")
        print("  %-24s off=0x%08x size=0x%08x H=%.3f%s"
              % (name, off, size, ent, tag))
    for a, b in hot_runs(entropy_blocks(data))[:12]:
        print("carve    : 0x%08x - 0x%08x (%d bytes, dd/binwalk)" % (a, b, b - a))
    for lang, note in [(l, n) for pat, l, n in LANGUAGE_SIGNS
                       if re.search(pat, data)]:
        print("toolchain: %-26s %s" % (lang, note))
    for name, why in [(n, w) for n, w in SUSPICIOUS_IMPORTS.items()
                      if re.search(rb"\b" + re.escape(n.encode()) + rb"\b", data)]:
        print("import   : %-26s %s" % (name, why))
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
    if target == "--selftest":
        assert abs(shannon(bytes(range(256)) * 4) - 8.0) < 1e-9
        assert hot_runs([(0, 7.9), (4096, 7.9), (8192, 3.0),
                         (12288, 7.95)]) == [(0, 8192), (12288, 16384)]
        print("selftest OK")
    else:
        report(target)
```

## Decision table - signal to next technique file

| Signal from triage | Conclusion | Open next |
| --- | --- | --- |
| `go1.2x` / `Go buildinf:` in strings | Go binary, symbols recoverable | `go-binaries` |
| `/rustc/<40hex>/library/...` | Rust | `rust-binaries` |
| `BSJB` / `mscoree.dll` / tiny .text in a PE | managed .NET | `dotnet-reversing` |
| `PyInstaller`, `MEIPASS`, `pyi-` | frozen Python | `python-bytecode-pyinstaller` |
| `cafe babe` magic, `.class`/`.jar` | JVM bytecode | `java-bytecode-reversing` |
| `UPX!` or section names `UPX0/UPX1` | UPX packed | `packers-and-unpacking` |
| `.text` entropy >= 7.5, tiny import table | custom packer | `packers-and-unpacking` |
| `_ZN`/`_ZSt` symbols, vtable-looking `.data.rel.ro` | C++ | `cpp-vtables-stl` |
| `\0asm` magic or `.wasm` | WebAssembly | `webassembly-reversing` |
| Mach-O + `objc_msgSend` / `_swift_` | Apple | `macho-objc-swift` |
| PE + `IsDebuggerPresent` / `NtQueryInformationProcess` | anti-debug | `anti-debug-bypass` |
| `ptrace(PTRACE_TRACEME)` in the ELF | anti-debug | `anti-debug-bypass` |
| `cpuid`, `VMware`, `VBox` strings | anti-VM | `anti-vm-bypass` |
| One giant function, `switch` on a byte array | custom VM | `custom-vm-bytecode` |
| Flat `while(1){switch(state)}` decompilation | CFG flattening | `obfuscation-deobfuscation` |
| Single `strcmp`/`memcmp` at the end | trivial | `dynamic-analysis-ltrace-ldpreload` |
| Long chain of arithmetic constraints on input | solve it | `angr-symbolic-execution`, `z3-constraint-solving` |
| Per-character timing/early-exit loop | side channel | `side-channel-instruction-counting` |
| No headers, huge, ARM/MIPS strings | firmware blob | `firmware-raw-blob-loading` |
| Position-independent, no headers, few KB | shellcode | `shellcode-analysis` |
| Everything normal, one check function | regular crackme | `ghidra-workflow`, `crackme-patterns` |

## Variants & pitfalls

- **`strings` misses UTF-16**: on PE add `-el`, or you conclude "no strings".
- **`strings` without `-a` skips data**: it scans only loadable, initialised ELF
  sections, so appended Go zips and PyInstaller archives are invisible.
- **High whole-file entropy is not proof of packing**: an embedded PNG is high
  entropy too. Packed = high-entropy `.text`, benign = `.rodata` or an overlay.
- **Low entropy does not disprove packing**: XOR-with-constant leaves entropy
  untouched, so check for an RWX segment plus a tiny import table.
- **A static binary is not hopeless**: Ghidra Function ID, IDA FLIRT or radare2
  `zignatures` re-label thousands of libc functions for you.
- **Do not trust the extension**: a `.jpg` is usually an ELF, a `.exe` often
  .NET, a UPX stub or a PyInstaller bundle.
- **`ltrace` shows nothing on a static binary** (no PLT): use `strace` plus a
  gdb breakpoint on the statically found `strcmp` address.
- **PIE offsets**: every `objdump` address is relative to the image base; gdb's
  `info proc mappings` gives the runtime base to add.
- **Fat Mach-O**: `lipo -thin arm64 -output chall.arm64 ./chall` first, or you
  analyse the wrong slice.
- **Running it**: container/VM, no network, throwaway home - CTF rev binaries
  do occasionally `rm -rf` or fork-bomb as a joke.

## Tools

- `file`, `strings`, `nm`, `objdump`, `readelf`, `c++filt` - GNU binutils;
  `checksec` (`pwn checksec` or the standalone script); `ltrace`, `strace`.
- `binwalk` - signature scan, entropy plot, recursive extraction; `ent` - byte
  entropy/chi-square.
- `pefile`, `pyelftools`, `LIEF` - parsers beyond the stdlib script above.
- `go version -m`, `GoReSym` - Go; `pyinstxtractor`, `uncompyle6`/`pycdc` -
  frozen Python; `ilspycmd`, `dnSpyEx`, `dotPeek` - .NET; `upx -d` - UPX.

## References

- GNU binutils manual - `strings`, `objdump`, `readelf`, `nm` options.
- ELF-64 Object File Format specification - section header layout, as parsed
  above; Microsoft PE Format documentation - data directory index 14 (the CLR
  descriptor) distinguishes a managed assembly from a native PE.
- Go source tree, `debug/buildinfo` - defines the `\xff Go buildinf:` magic.
- binwalk project documentation - signature scanning and entropy analysis.
