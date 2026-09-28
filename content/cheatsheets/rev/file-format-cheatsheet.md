---
title: "Executable File Formats - ELF, PE and Mach-O Header Reference"
category: rev
subcategory: file-formats
type: reference
tags: [elf, pe, macho, file-format, header, sections, segments, magic-bytes, readelf, objdump, otool, rabin2, pefile, program-headers, data-directory, load-commands, relocations, dynamic-section]
summary: "Byte-exact ELF, PE and Mach-O header layouts with field offsets, what each section means, and the command to dump every part of each."
tools: [readelf, objdump, otool, rabin2, pefile, xxd, nm]
related: [assembly-cheatsheet, windows-pe-reversing, macho-objc-swift, triage-unknown-binary, binary-patching, firmware-raw-blob-loading]
---

## Magic bytes

```
7f 45 4c 46            ELF            (\x7fELF)
4d 5a                  PE / MZ        ("MZ", PE header at *(u32*)0x3c)
fe ed fa ce            Mach-O 32 BE-read / thin, little-endian file
ce fa ed fe            Mach-O 32 (MH_CIGAM)
fe ed fa cf            Mach-O 64 (MH_MAGIC_64)
cf fa ed fe            Mach-O 64 (MH_CIGAM_64)  <- what you usually see
ca fe ba be            Mach-O universal (FAT) -- OR a Java .class file
ca fe ba bf            Mach-O universal 64-bit
ca fe d0 0d            Java JAR (pack200)
50 4b 03 04            ZIP / JAR / APK / DOCX / ASAR-adjacent
1f 8b 08               gzip
42 5a 68               bzip2
fd 37 7a 58 5a         xz
5d 00 00               LZMA (alone)
04 22 4d 18            LZ4
28 b5 2f fd            zstd
68 73 71 73 / 73 71 73 68   squashfs ("hsqs"/"sqsh" - endianness tells you the target)
27 05 19 56            U-Boot uImage
d0 cf 11 e0 a1 b1 1a e1    OLE2 (legacy .doc/.xls)
25 50 44 46            PDF ("%PDF")
00 61 73 6d            WebAssembly ("\0asm")
de c0 17 0b            LLVM bitcode
4d 53 43 46            Microsoft cabinet ("MSCF")
7f 45 4c 46 02 01 01   ELF64 little-endian SysV
```

```sh
# Identify anything
file ./target
xxd -l 16 ./target
rabin2 -I ./target
binwalk ./target          # finds embedded formats too
```

## ELF

### ELF64 header (`Elf64_Ehdr`, 64 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 4 | `e_ident[EI_MAG]` | `7f 45 4c 46` |
| 0x04 | 1 | `EI_CLASS` | 1 = 32-bit, 2 = 64-bit |
| 0x05 | 1 | `EI_DATA` | 1 = little-endian, 2 = big-endian |
| 0x06 | 1 | `EI_VERSION` | 1 |
| 0x07 | 1 | `EI_OSABI` | 0 SysV, 3 Linux, 9 FreeBSD |
| 0x08 | 1 | `EI_ABIVERSION` | |
| 0x09 | 7 | padding | |
| 0x10 | 2 | `e_type` | 1 REL, 2 EXEC, 3 DYN (PIE or .so), 4 CORE |
| 0x12 | 2 | `e_machine` | 3 = x86, 0x3E = x86-64, 0x28 = ARM, 0xB7 = AArch64, 8 = MIPS, 0xF3 = RISC-V |
| 0x14 | 4 | `e_version` | 1 |
| 0x18 | 8 | `e_entry` | entry point virtual address |
| 0x20 | 8 | `e_phoff` | program header table offset (usually 0x40) |
| 0x28 | 8 | `e_shoff` | section header table offset |
| 0x30 | 4 | `e_flags` | arch-specific (MIPS ABI bits, ARM EABI version) |
| 0x34 | 2 | `e_ehsize` | 64 |
| 0x36 | 2 | `e_phentsize` | 56 |
| 0x38 | 2 | `e_phnum` | number of program headers |
| 0x3A | 2 | `e_shentsize` | 64 |
| 0x3C | 2 | `e_shnum` | number of section headers |
| 0x3E | 2 | `e_shstrndx` | index of the section-name string table |

ELF32 shrinks the address fields to 4 bytes: `e_entry` 0x18, `e_phoff` 0x1C, `e_shoff` 0x20,
`e_ehsize` 0x28, header size 52, phentsize 32, shentsize 40.

### Program header (`Elf64_Phdr`, 56 bytes) - what the loader uses

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | `p_type` (1 LOAD, 2 DYNAMIC, 3 INTERP, 4 NOTE, 6 PHDR, 7 TLS, 0x6474e550 GNU_EH_FRAME, 0x6474e551 GNU_STACK, 0x6474e552 GNU_RELRO) |
| 0x04 | 4 | `p_flags` (1 X, 2 W, 4 R) |
| 0x08 | 8 | `p_offset` (file offset) |
| 0x10 | 8 | `p_vaddr` (virtual address) |
| 0x18 | 8 | `p_paddr` |
| 0x20 | 8 | `p_filesz` |
| 0x28 | 8 | `p_memsz` (larger than filesz => .bss) |
| 0x30 | 8 | `p_align` |

**vaddr -> file offset**: find the PT_LOAD with `p_vaddr <= vaddr < p_vaddr + p_filesz`,
then `offset = p_offset + (vaddr - p_vaddr)`. This is the calculation you need for patching.

### Section header (`Elf64_Shdr`, 64 bytes)

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | `sh_name` (index into .shstrtab) |
| 0x04 | 4 | `sh_type` (1 PROGBITS, 2 SYMTAB, 3 STRTAB, 4 RELA, 8 NOBITS, 9 REL, 11 DYNSYM) |
| 0x08 | 8 | `sh_flags` (1 WRITE, 2 ALLOC, 4 EXECINSTR, 0x20 STRINGS, 0x40 INFO_LINK) |
| 0x10 | 8 | `sh_addr` |
| 0x18 | 8 | `sh_offset` |
| 0x20 | 8 | `sh_size` |
| 0x28 | 4 | `sh_link` |
| 0x2C | 4 | `sh_info` |
| 0x30 | 8 | `sh_addralign` |
| 0x38 | 8 | `sh_entsize` |

### ELF sections and what they mean

| Section | Contents |
|---|---|
| `.text` | executable code |
| `.rodata` | read-only constants: strings, jump tables, lookup tables, expected flags |
| `.data` | initialised writable globals |
| `.bss` | zero-initialised globals (no file bytes) |
| `.plt` / `.plt.sec` | lazy-binding stubs for imported functions |
| `.got` / `.got.plt` | pointers patched by the loader; `.got.plt` is the lazy one |
| `.rela.dyn` / `.rela.plt` | relocations (x86-64 uses RELA; x86/ARM32 use REL) |
| `.dynsym` / `.dynstr` | dynamic symbols and their names (survive stripping) |
| `.symtab` / `.strtab` | full symbols (removed by `strip`) |
| `.init` / `.fini` | pre-main and post-main code |
| `.init_array` / `.fini_array` | arrays of constructor/destructor pointers - **code that runs before main** |
| `.eh_frame` / `.eh_frame_hdr` | unwind tables; give function boundaries even when stripped |
| `.gcc_except_table` | C++ exception landing-pad tables |
| `.comment` | compiler version string |
| `.note.gnu.build-id` | 20-byte build id |
| `.note.go.buildid` / `.gopclntab` / `.go.buildinfo` | Go binary metadata |
| `.tbss` / `.tdata` | thread-local storage |
| `.interp` | path to the dynamic loader |

### Dynamic section tags (`readelf -d`)

| Tag | Meaning |
|---|---|
| `NEEDED` | a required shared library |
| `SONAME` | this library's own name |
| `RPATH` / `RUNPATH` | library search paths (a classic privesc/hijack angle) |
| `INIT` / `FINI` / `INIT_ARRAY` | constructors |
| `SYMBOLIC` | prefer own symbols over global ones |
| `BIND_NOW` / `FLAGS_1 NOW` | full RELRO: the GOT is resolved and read-only at startup |
| `TEXTREL` | writable text (self-modifying or badly built) |

### ELF commands

```sh
readelf -h ./chall            # header
readelf -l -W ./chall         # program headers + section-to-segment mapping
readelf -S -W ./chall         # section headers
readelf -d ./chall            # dynamic section (NEEDED, RPATH, RELRO)
readelf -s ./chall            # symbols (.symtab and .dynsym)
readelf -r ./chall            # relocations
readelf -n ./chall            # notes (build-id, ABI tag, Go build id)
readelf -x .rodata ./chall    # hexdump a section
readelf -p .comment ./chall   # strings of a section (compiler version)
objdump -d ./chall            # disassemble executable sections
objdump -D ./chall            # disassemble everything, including data
objdump -s -j .rodata ./chall # full contents of one section
objdump -T ./chall            # dynamic symbol table
objdump -R ./chall            # dynamic relocations
objdump -p ./chall            # program headers, in objdump's format
nm -C ./chall                 # symbols, demangled
nm -D ./chall                 # dynamic symbols only (works on stripped binaries)
ldd ./chall                   # resolved shared libraries (runs the loader - careful)
strings -a -t x ./chall       # strings with file offsets
checksec --file=./chall       # RELRO/canary/NX/PIE/RPATH summary (pwntools or checksec.sh)
rabin2 -I ./chall             # the same summary from radare2
```

### Hardening flags and what they look like

| Feature | How to see it |
|---|---|
| NX | `readelf -l` shows `GNU_STACK` with `RW` (no `E`) |
| PIE | `readelf -h` says `Type: DYN` and there is an `INTERP` |
| Partial RELRO | a `GNU_RELRO` segment exists |
| Full RELRO | `readelf -d` shows `BIND_NOW` / `FLAGS_1: NOW` |
| Stack canary | `__stack_chk_fail` in the symbol table |
| FORTIFY | `__*_chk` symbols (`__printf_chk`, `__memcpy_chk`) |
| Stripped | `readelf -s` shows only `.dynsym`, and `file` says "stripped" |
| Static | no `INTERP`, no `NEEDED`, large size |

## PE (Windows)

### Layout

```
0x00              IMAGE_DOS_HEADER  ("MZ", 64 bytes)
0x3C  (u32)       e_lfanew -> offset of the NT headers
0x40..e_lfanew    DOS stub ("This program cannot be run in DOS mode") + Rich header
e_lfanew          IMAGE_NT_HEADERS
  +0x00  4        Signature "PE\0\0"
  +0x04  20       IMAGE_FILE_HEADER
  +0x18  ...      IMAGE_OPTIONAL_HEADER (224 bytes PE32, 240 bytes PE32+)
  ...             IMAGE_SECTION_HEADER[NumberOfSections] (40 bytes each)
```

### IMAGE_FILE_HEADER (20 bytes, at `e_lfanew + 4`)

| Offset | Size | Field | Notes |
|---|---|---|---|
| +0x00 | 2 | `Machine` | 0x014C i386, 0x8664 x64, 0x01C4 ARMNT, 0xAA64 ARM64 |
| +0x02 | 2 | `NumberOfSections` | |
| +0x04 | 4 | `TimeDateStamp` | unix epoch of the link (often a build fingerprint) |
| +0x08 | 4 | `PointerToSymbolTable` | usually 0 |
| +0x0C | 4 | `NumberOfSymbols` | usually 0 |
| +0x10 | 2 | `SizeOfOptionalHeader` | 224 (PE32) or 240 (PE32+) |
| +0x12 | 2 | `Characteristics` | 0x2 EXECUTABLE_IMAGE, 0x2000 DLL, 0x20 LARGE_ADDRESS_AWARE |

### IMAGE_OPTIONAL_HEADER (offsets relative to its start, `e_lfanew + 0x18`)

| Offset | Size | Field |
|---|---|---|
| +0x00 | 2 | `Magic` (0x10B PE32, 0x20B PE32+) |
| +0x02 | 2 | Major/Minor LinkerVersion |
| +0x04 | 4 | `SizeOfCode` |
| +0x10 | 4 | `AddressOfEntryPoint` (RVA) |
| +0x14 | 4 | `BaseOfCode` |
| +0x18 | 4/8 | `ImageBase` (PE32: +0x1C as u32; PE32+: +0x18 as u64) |
| +0x20 | 4 | `SectionAlignment` |
| +0x24 | 4 | `FileAlignment` |
| +0x38 | 4 | `SizeOfImage` |
| +0x3C | 4 | `SizeOfHeaders` |
| +0x40 | 4 | `CheckSum` |
| +0x44 | 2 | `Subsystem` (2 GUI, 3 console, 1 native/driver) |
| +0x46 | 2 | `DllCharacteristics` (0x40 DYNAMIC_BASE/ASLR, 0x100 NX_COMPAT, 0x400 NO_SEH, 0x4000 CFG) |
| +0x60 (PE32) / +0x70 (PE32+) | 8*16 | `DataDirectory[16]` |

### Data directories (index -> meaning)

| # | Directory | Use in RE |
|---|---|---|
| 0 | Export | a DLL's exported functions |
| 1 | **Import** | which APIs the binary uses - read this first |
| 2 | Resource | icons, dialogs, RCDATA payloads |
| 3 | Exception (`.pdata`) | x64 unwind info = free function boundaries |
| 4 | Security | Authenticode signature (lives in the overlay) |
| 5 | BaseReloc | needed for ASLR |
| 6 | Debug | PDB path, build id |
| 9 | **TLS** | `AddressOfCallBacks` - code that runs before the entry point |
| 10 | Load Config | CFG tables, SafeSEH table |
| 12 | IAT | the import address table |
| 13 | Delay Import | lazily resolved imports |
| 14 | **COM descriptor** | non-zero => this is a .NET assembly |

### IMAGE_SECTION_HEADER (40 bytes)

| Offset | Size | Field |
|---|---|---|
| +0x00 | 8 | `Name` (ASCII, not NUL-terminated if 8 chars) |
| +0x08 | 4 | `VirtualSize` |
| +0x0C | 4 | `VirtualAddress` (RVA) |
| +0x10 | 4 | `SizeOfRawData` |
| +0x14 | 4 | `PointerToRawData` (file offset) |
| +0x24 | 4 | `Characteristics` (0x20000000 EXECUTE, 0x40000000 READ, 0x80000000 WRITE, 0x00000020 CODE) |

**RVA -> file offset**: find the section with
`VirtualAddress <= rva < VirtualAddress + max(VirtualSize, SizeOfRawData)`, then
`offset = PointerToRawData + (rva - VirtualAddress)`. A virtual address is
`ImageBase + RVA`.

### Typical section names

| Name | Contents |
|---|---|
| `.text` | code |
| `.rdata` | read-only data, the import/export tables, C++ RTTI |
| `.data` | writable globals |
| `.bss` | zero-init (often merged into `.data`) |
| `.idata` / `.edata` | import / export (usually folded into `.rdata`) |
| `.rsrc` | resources |
| `.reloc` | base relocations |
| `.pdata` | exception/unwind info (x64) |
| `.tls` | thread-local storage |
| `UPX0`/`UPX1`, `.aspack`, `.themida`, `.vmp0` | packer artefacts |
| `.textbss` | debug-build placeholder, or a packer's writable code section |

### PE commands

```sh
rabin2 -I chall.exe          # summary: arch, bits, subsystem, nx, pic, .NET or not
rabin2 -S chall.exe          # sections
rabin2 -i chall.exe          # imports
rabin2 -E chall.exe          # exports
rabin2 -H chall.exe          # header fields
rabin2 -z chall.exe          # strings
objdump -x chall.exe         # everything objdump understands about a PE
objdump -d -M intel chall.exe
wrestool -l chall.exe        # resources
python3 -c "import pefile,sys; print(pefile.PE(sys.argv[1]).dump_info())" chall.exe
# On Windows with MSVC tools:
dumpbin /headers /imports /exports /section chall.exe
# Hash the rich header / imports for sample clustering
python3 -c "import pefile,sys; p=pefile.PE(sys.argv[1]); print(p.get_imphash())" chall.exe
```

## Mach-O (macOS / iOS)

### mach_header_64 (32 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 4 | `magic` | `cf fa ed fe` (MH_MAGIC_64, little-endian file) |
| 0x04 | 4 | `cputype` | 0x01000007 x86_64, 0x0100000C arm64, 7 i386, 12 arm |
| 0x08 | 4 | `cpusubtype` | arm64e = arm64 with subtype 2 |
| 0x0C | 4 | `filetype` | 2 EXECUTE, 6 DYLIB, 8 BUNDLE, 10 DSYM, 1 OBJECT |
| 0x10 | 4 | `ncmds` | number of load commands |
| 0x14 | 4 | `sizeofcmds` | total bytes of load commands |
| 0x18 | 4 | `flags` | 0x200000 PIE, 0x1 NOUNDEFS, 0x80 TWOLEVEL |
| 0x1C | 4 | `reserved` | (64-bit only) |

Load commands follow immediately, each `{ uint32 cmd; uint32 cmdsize; ... }`.

### Load commands you will read

| cmd | Name | Contents |
|---|---|---|
| 0x19 | `LC_SEGMENT_64` | segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects |
| 0x02 | `LC_SYMTAB` | symbol table offset/count, string table offset/size |
| 0x0B | `LC_DYSYMTAB` | local/external/undefined symbol ranges, indirect symbols |
| 0x0C | `LC_LOAD_DYLIB` | a required library + version |
| 0x0D | `LC_ID_DYLIB` | this dylib's install name |
| 0x0E | `LC_LOAD_DYLINKER` | `/usr/lib/dyld` |
| 0x1B | `LC_UUID` | build UUID (matches the dSYM) |
| 0x1C | `LC_RPATH` | `@executable_path/../Frameworks` |
| 0x1D | `LC_CODE_SIGNATURE` | signature blob in `__LINKEDIT` |
| 0x26 | `LC_FUNCTION_STARTS` | ULEB deltas = every function address, even when stripped |
| 0x2C | `LC_ENCRYPTION_INFO_64` | `cryptid` != 0 means `__TEXT` is FairPlay-encrypted |
| 0x32 | `LC_BUILD_VERSION` | platform, min OS, SDK |
| 0x80000028 | `LC_MAIN` | entry point as a file offset + initial stack size |
| 0x80000022 | `LC_DYLD_INFO_ONLY` | rebase/bind/lazy-bind/export opcode streams |
| 0x80000034 | `LC_DYLD_CHAINED_FIXUPS` | the modern replacement for the above |

### section_64 (80 bytes, inside a segment)

| Offset | Size | Field |
|---|---|---|
| 0x00 | 16 | `sectname` |
| 0x10 | 16 | `segname` |
| 0x20 | 8 | `addr` |
| 0x28 | 8 | `size` |
| 0x30 | 4 | `offset` (file offset) |
| 0x34 | 4 | `align` (power of two) |
| 0x38 | 4 | `reloff` |
| 0x3C | 4 | `nreloc` |
| 0x40 | 4 | `flags` |

### Segments and sections

| Segment,Section | Contents |
|---|---|
| `__TEXT,__text` | code |
| `__TEXT,__stubs` / `__stub_helper` | the PLT equivalent |
| `__TEXT,__cstring` | C string literals |
| `__TEXT,__const` | read-only constants |
| `__TEXT,__objc_methname` | Objective-C selector names |
| `__TEXT,__objc_classname` | class name strings |
| `__TEXT,__unwind_info` | compact unwind (function boundaries) |
| `__TEXT,__swift5_types` / `__swift5_proto` | Swift metadata |
| `__DATA_CONST,__got` | the GOT equivalent |
| `__DATA,__la_symbol_ptr` | lazy symbol pointers |
| `__DATA,__objc_classlist` | pointers to ObjC class structures |
| `__DATA,__objc_selrefs` | selector references (the xrefs you need) |
| `__DATA,__cfstring` | `@"literal"` CFString structs (pointer into `__cstring`) |
| `__DATA,__bss` | zero-initialised |
| `__LINKEDIT` | symbol table, string table, relocations, code signature |

### FAT / universal header (big-endian!)

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | `magic` = `ca fe ba be` |
| 0x04 | 4 | `nfat_arch` |
| then per arch, 20 bytes | | `cputype, cpusubtype, offset, size, align` |

Note the collision with Java `.class` (`ca fe ba be` too). Disambiguate by the next field:
a Java class has a version number there (e.g. `00 00 00 37`), a fat Mach-O has a small
architecture count.

### Mach-O commands

```sh
lipo -info ./chall                    # which architectures are in the file
lipo -thin arm64 ./chall -output ./chall.arm64
otool -h ./chall                      # header
otool -l ./chall                      # all load commands (the master view)
otool -L ./chall                      # linked dylibs
otool -tV ./chall                     # disassembly with symbols
otool -s __TEXT __cstring ./chall     # dump a section
otool -I ./chall                      # indirect symbol table (stubs)
nm -m ./chall                         # symbols with attributes
vtool -show ./chall                   # build/platform info
codesign -dvvv ./chall                # signing info
codesign -d --entitlements - ./chall  # entitlements
dyld_info -exports ./chall            # exported symbols (modern replacement for some otool)
rabin2 -I ./chall                     # radare2's cross-format summary
size -m ./chall                       # per-segment/section sizes
```

## Cross-format quick comparison

| Concept | ELF | PE | Mach-O |
|---|---|---|---|
| Magic | `\x7fELF` | `MZ` + `PE\0\0` | `cf fa ed fe` |
| Loadable unit | PT_LOAD segment | section | LC_SEGMENT_64 |
| Code | `.text` | `.text` | `__TEXT,__text` |
| Read-only data | `.rodata` | `.rdata` | `__TEXT,__const`/`__cstring` |
| Imports | `.dynsym` + `.rela.plt` | Import directory | LC_DYLD_INFO binds / chained fixups |
| Import stubs | `.plt` | thunks into the IAT | `__stubs` |
| Import pointer table | `.got.plt` | IAT | `__got`/`__la_symbol_ptr` |
| Pre-main code | `.init_array` | TLS callbacks + CRT init | `__mod_init_func` |
| Relocations | `.rela.*` | `.reloc` | rebase opcodes / chained fixups |
| Function boundaries when stripped | `.eh_frame` | `.pdata` (x64) | `LC_FUNCTION_STARTS` |
| Dump tool | `readelf`/`objdump` | `dumpbin`/`rabin2` | `otool` |
| Base address | `p_vaddr` of the first PT_LOAD | `ImageBase` + RVA | `vmaddr` of `__TEXT` (usually 0x100000000) |
| Address -> file offset | `p_offset + (va - p_vaddr)` | `PointerToRawData + (rva - VirtualAddress)` | `sec.offset + (addr - sec.addr)` |

## One-liners

```sh
# Which format is this, really?
for f in *; do printf '%-24s ' "$f"; xxd -l 4 -p "$f"; done

# Entry point of each format
readelf -h a.out | grep Entry
rabin2 -I a.exe | grep baddr
otool -l a.macho | grep -A2 LC_MAIN

# Extract a section to a file
objcopy --dump-section .rodata=rodata.bin ./chall            # ELF
otool -s __TEXT __cstring ./chall | tail -n +2 | cut -d$'\t' -f2 > strings.txt   # Mach-O
python3 -c "import pefile,sys; p=pefile.PE(sys.argv[1]); open('sec.bin','wb').write(p.sections[0].get_data())" a.exe

# Is it stripped?
file ./chall | grep -o 'not stripped\|stripped'
readelf -s ./chall | grep -c FUNC

# Find the overlay (data past the last section) of a PE
python3 -c "
import pefile,sys
p = pefile.PE(sys.argv[1])
end = max(s.PointerToRawData + s.SizeOfRawData for s in p.sections)
print('overlay at', hex(end), 'size', len(p.__data__) - end)
" a.exe
```

## References

- `man 5 elf` and the System V ABI / gABI documents for the ELF structure layouts.
- Microsoft "PE Format" specification for the IMAGE_* structures and data directory indices.
- Apple's `<mach-o/loader.h>` and `<mach-o/fat.h>` headers for the Mach-O structures.
