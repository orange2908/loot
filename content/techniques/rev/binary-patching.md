---
title: "Binary Patching - NOP the Check, Keep the ELF Valid"
category: rev
subcategory: patching
type: technique
tags: [binary-patching, patch, nop, jump-inversion, objcopy, keystone, lief, pyelftools, radare2, ghidra, ida, ropper, elf, pe, file-offset, virtual-address, anti-debug, crackme, hex-editor]
difficulty: easy
summary: "Turn a failing check into a passing one: map vaddr to file offset, flip je/jne, NOP a call, or inject a segment with LIEF - without corrupting the binary."
when_to_use:
  - "A check blocks execution (license, anti-debug, root check) and you only need the code after it"
  - "You want to run a packed/obfuscated binary past its self-check to reach the interesting code"
  - "You need to stub out a slow or environment-dependent function before feeding the binary to angr/Unicorn"
  - "A CTF asks you to make the binary print the flag rather than to recover an input"
tools: [radare2, ghidra, ida, keystone, lief, pyelftools, objcopy, ropper, xxd]
related: [anti-debug-bypass, anti-vm-bypass, dynamic-analysis-ltrace-ldpreload, triage-unknown-binary, crackme-patterns]
---

## TL;DR

Patching replaces bytes in the file (or in memory) so a branch goes the way you want.
Two hard parts: (1) translating the address your disassembler shows into a *file offset*,
and (2) keeping the instruction stream the same length so nothing downstream shifts.
Same-length patches are always safe; anything that changes size needs LIEF or a new segment.

## Recognise it

- The decompiler shows `if (check(input) == 0) { puts("Wrong"); exit(1); } print_flag();`
  and `print_flag` builds the flag locally - patch, do not solve.
- `ptrace(PTRACE_TRACEME, 0, 0, 0)` returning -1 kills the process under gdb - NOP the call.
- A `cpuid` / `/proc/self/status` / `getenv("LD_PRELOAD")` check aborts in your environment.
- A loop verifies a checksum of `.text` before running - patch the comparison, not the data.

## Virtual address to file offset

For a non-PIE ELF the addresses in the disassembler are virtual. Each section header has
both `Address` (vaddr) and `Offset` (file offset):

```sh
# Section headers: pick the section containing your vaddr, then off = vaddr - addr + offset
readelf -S -W ./chall
# Program headers do the same thing at segment granularity (more reliable for stripped files)
readelf -l -W ./chall
```

If `.text` is at vaddr `0x401136` with file offset `0x1136`, the delta is `0x400000`. For a
PIE binary (`ET_DYN`) the vaddrs in Ghidra are usually already offsets plus an image base of
`0x100000` (Ghidra) or `0x0` (objdump); subtract whatever base your tool used.

```sh
# Confirm what a byte at a file offset currently is before writing to it
xxd -s 0x1136 -l 16 ./chall
# Disassemble around a virtual address to double-check the instruction boundary
objdump -d --start-address=0x401130 --stop-address=0x401160 ./chall
```

## The patch byte table (x86 / x86-64)

| Goal | Original | Patch | Note |
|---|---|---|---|
| Invert a short conditional | `74 xx` (je) | `75 xx` (jne) | 1 byte, always safe |
| Invert a near conditional | `0f 84 xx xx xx xx` | `0f 85 ...` | same length |
| Always take the branch | `74 xx` | `eb xx` (jmp short) | same length |
| Never take the branch | `74 xx` | `90 90` | two NOPs |
| Kill a 5-byte call | `e8 xx xx xx xx` | `90 90 90 90 90` | return value is garbage |
| Force a function to return 1 | first bytes | `b8 01 00 00 00 c3` | `mov eax,1; ret` |
| Force a function to return 0 | first bytes | `31 c0 c3` | `xor eax,eax; ret` |
| Force a 64-bit return 0 | first bytes | `48 31 c0 c3` | `xor rax,rax; ret` |
| Skip a syscall wrapper | `0f 05` | `90 90` | syscall -> nop nop |
| Make `exit()` a no-op | its PLT stub | `c3` | ret |
| Multi-byte NOP (keep alignment) | - | `66 0f 1f 44 00 00` | 6-byte canonical nop |

AArch64 equivalents (all instructions are 4 bytes, so patching is easy):

| Goal | Patch bytes (little-endian) | Mnemonic |
|---|---|---|
| No-op | `1f 20 03 d5` | `nop` |
| Return | `c0 03 5f d6` | `ret` |
| Return 0 | `00 00 80 d2` + ret | `mov x0, #0` |
| Return 1 | `20 00 80 d2` + ret | `mov x0, #1` |
| Invert b.eq/b.ne | flip low nibble of cond field | `b.eq` 0x0 <-> `b.ne` 0x1 |

## Workflow

1. Find the instruction in a disassembler and note its **virtual address** and **length**.
2. Convert to a file offset (script below, or `readelf -S`).
3. Decide the replacement with the same total length. Pad with `90` (x86) or `nop` (ARM).
4. Write the bytes on a **copy** of the file. Never patch in place without a backup.
5. Verify: `cmp -l orig patched` should list exactly the bytes you meant to change, and
   `objdump -d` around the address should show sane instructions (no split mid-instruction).
6. Run it. If it segfaults immediately you probably desynced the instruction stream.

## Tool-by-tool

```sh
# --- radare2: open in write mode, seek, assemble in place -------------------
r2 -w ./chall
# [0x00401050]> s 0x401234          ; seek to the check
# [0x00401234]> pd 4                ; look before you write
# [0x00401234]> wao nop             ; NOP the current instruction (keeps length)
# [0x00401234]> wao ret1            ; make the current function return 1
# [0x00401234]> wa jmp 0x401290     ; assemble an instruction at the cursor
# [0x00401234]> wx 9090             ; raw hex write
# [0x00401234]> wao jz              ; convert the conditional jump to jz
# [0x00401234]> q

# One-shot, scriptable (no interactive session)
r2 -w -q -c 's 0x401234; wx 9090' ./chall

# Diff the patched file against the original at byte level
radiff2 -x ./chall.orig ./chall
```

```sh
# --- objcopy / dd: raw surgery ---------------------------------------------
# Dump a section to a file, edit it, put it back (section size must not change)
objcopy --dump-section .text=text.bin ./chall
# ... edit text.bin with a hex editor or python ...
objcopy --update-section .text=text.bin ./chall ./chall.patched

# Poke two bytes at file offset 0x1236 without touching anything else
printf '\x90\x90' | dd of=./chall bs=1 seek=$((0x1236)) conv=notrunc

# Strip a troublesome section entirely (e.g. a .init_array anti-debug ctor)
objcopy --remove-section .init_array ./chall ./chall.noctor
```

**Ghidra**: select the instruction, `Ctrl+Shift+G` (Patch Instruction), type `NOP` or
`JMP 0x401290`, then `File > Export Program... > Format: Original File` to write a real
binary back out (the "Binary" format exports only the bytes of the current view - not what
you want). Ghidra will keep the length only if your replacement fits; pad with NOPs yourself.

**IDA Pro**: `Edit > Patch program > Change byte / Assemble`, then
`Edit > Patch program > Apply patches to input file`. IDA does *not* write patches to disk
until you run that last command. The `Assemble` dialog pads with NOPs on request.

**Binary Ninja**: right-click an instruction, `Patch > Invert Branch` / `Never Branch` /
`Always Branch` / `Nop`, then `File > Save Contents As`. This is the fastest of the four.

**x64dbg (Windows)**: space to assemble, then `File > Patch file` (Ctrl+P) to write the PE.

## Code

Same-length patcher with proper vaddr->offset translation:

```python
#!/usr/bin/env python3
"""patch.py - write bytes at a virtual address in an ELF, same-length only.

Usage:
    python3 patch.py ./chall 0x401234 9090            # raw hex
    python3 patch.py ./chall 0x401234 "jmp 0x401290"  # needs keystone

Requires: pyelftools (pip install pyelftools); keystone-engine only for asm mode.
"""
import shutil
import sys

from elftools.elf.elffile import ELFFile


def vaddr_to_off(path: str, vaddr: int) -> int:
    """Translate a virtual address to a file offset using the program headers."""
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            start = seg["p_vaddr"]
            end = start + seg["p_filesz"]
            if start <= vaddr < end:
                return seg["p_offset"] + (vaddr - start)
    raise ValueError(f"vaddr {vaddr:#x} is not inside any PT_LOAD segment")


def assemble(text: str, addr: int, arch: str = "x64") -> bytes:
    """Assemble one or more ';'-separated instructions at `addr`."""
    from keystone import KS_ARCH_ARM64, KS_ARCH_X86, KS_MODE_32, KS_MODE_64, KS_MODE_LITTLE_ENDIAN, Ks

    modes = {
        "x64": (KS_ARCH_X86, KS_MODE_64),
        "x86": (KS_ARCH_X86, KS_MODE_32),
        "arm64": (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),
    }
    ks = Ks(*modes[arch])
    encoding, _count = ks.asm(text, addr)
    return bytes(encoding)


def patch(path: str, vaddr: int, data: bytes, out: str | None = None) -> str:
    out = out or path + ".patched"
    shutil.copyfile(path, out)
    off = vaddr_to_off(path, vaddr)
    with open(out, "r+b") as fh:
        fh.seek(off)
        old = fh.read(len(data))
        fh.seek(off)
        fh.write(data)
    print(f"[+] {vaddr:#x} -> file offset {off:#x}")
    print(f"    old: {old.hex(' ')}")
    print(f"    new: {data.hex(' ')}")
    return out


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    path, vaddr_s, payload = sys.argv[1], sys.argv[2], sys.argv[3]
    vaddr = int(vaddr_s, 0)
    try:
        data = bytes.fromhex(payload.replace(" ", ""))
    except ValueError:
        data = assemble(payload, vaddr)
    out = patch(path, vaddr, data)
    print(f"[+] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Bulk NOP of a virtual address range (handy for killing a whole anti-debug block):

```python
#!/usr/bin/env python3
"""nop_range.py - NOP out [start, end) of an ELF (x86 only: 0x90 filler)."""
import shutil
import sys

from elftools.elf.elffile import ELFFile


def seg_off(path: str, vaddr: int) -> int:
    with open(path, "rb") as fh:
        for seg in ELFFile(fh).iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_vaddr"] <= vaddr < seg["p_vaddr"] + seg["p_filesz"]:
                return seg["p_offset"] + vaddr - seg["p_vaddr"]
    raise ValueError("vaddr not mapped")


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: nop_range.py <elf> <start_vaddr> <end_vaddr>")
        return 1
    path, start, end = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
    if end <= start:
        print("end must be > start")
        return 1
    out = path + ".nop"
    shutil.copyfile(path, out)
    with open(out, "r+b") as fh:
        fh.seek(seg_off(path, start))
        fh.write(b"\x90" * (end - start))
    print(f"[+] NOPed {end - start} bytes -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

When a same-length patch is not enough (you need to *add* code), add a segment with LIEF and
repoint the entry point:

```python
#!/usr/bin/env python3
"""inject.py - append an executable segment of shellcode to an ELF and run it first.

The original entry point is restored afterwards by the stub you supply, or you can simply
jump back with a tail `jmp original_entry` appended to your payload.
"""
import sys

import lief


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: inject.py <elf> <raw_shellcode.bin>")
        return 1
    binary = lief.parse(sys.argv[1])
    with open(sys.argv[2], "rb") as fh:
        code = list(fh.read())

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.SEGMENT_TYPES.LOAD
    segment.flags = lief.ELF.SEGMENT_FLAGS(
        lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.X
    )
    segment.content = code
    segment.alignment = 0x1000

    new_seg = binary.add(segment)
    print(f"[+] payload mapped at {new_seg.virtual_address:#x}")
    print(f"[+] old entrypoint    {binary.header.entrypoint:#x}")
    binary.header.entrypoint = new_seg.virtual_address
    binary.write(sys.argv[1] + ".injected")
    print(f"[+] wrote {sys.argv[1]}.injected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Verifying the patch

```sh
# Exactly which bytes changed (offset is 1-based in cmp output!)
cmp -l ./chall.orig ./chall.patched
# Re-disassemble the patched region and make sure nothing desynced
objdump -d --start-address=0x401220 --stop-address=0x401260 ./chall.patched
# Confirm the ELF still parses and segments are sane
readelf -l -W ./chall.patched >/dev/null && echo "ELF OK"
# Make it executable again after objcopy/dd round-trips
chmod +x ./chall.patched
```

## Variants & pitfalls

- **Patching a PIE at runtime instead of on disk** is often easier: in gdb, break at the
  check and `set $eflags |= 0x40` (set ZF) or `jump *0x...`. Use `gdb -ex 'set {char}0x555555555234 = 0x75'`
  after ASLR resolution rather than fighting file offsets.
- **Self-checksumming binaries** verify `.text` before running. Patch the *comparison* in the
  checksum routine (or its return value) instead of the code it hashes, or patch in memory
  after the check has passed.
- **Do not change lengths.** Deleting a byte shifts every following instruction and every
  relative offset silently: the binary will still load and then crash somewhere unrelated.
- **Relative jumps are relative to the *next* instruction.** `eb xx` displacement is
  `target - (addr_of_jmp + 2)`, sign-extended 8-bit, so range is -128..+127. If your target is
  further away you need `e9 xx xx xx xx` (5 bytes) - which may not fit.
- **PLT calls**: NOPing `call puts@plt` is fine, but NOPing a call whose return value is used
  leaves garbage in `eax`; prefer patching the *callee's* first bytes to `xor eax,eax; ret`.
- **PE files**: virtual address = RVA + ImageBase; use `pefile` (`pe.get_offset_from_rva(rva)`)
  instead of pyelftools. A patched PE with an Authenticode signature will fail signature
  checks - strip the certificate directory or ignore the warning.
- **Mach-O**: code signature invalidation means macOS will kill the process. Re-sign with
  `codesign -f -s - ./chall` (ad-hoc) after patching.
- **Packed binaries**: patching the packed file does nothing useful; unpack first (see
  `packers-and-unpacking`) or patch in memory after the OEP.
- **Ghidra's exported file can be larger** than the original if you used "Binary" export.
  Always use "Original File".

## Tools

- `radare2` / `rizin` - `-w` write mode, `wa`/`wx`/`wao`, `radiff2 -x` for verification.
- `keystone-engine` - assembler as a Python library, any arch.
- `LIEF` - add/modify sections and segments, change entrypoints, rewrite PE imports.
- `pyelftools` / `pefile` - address translation and header parsing.
- `ropper --file bin --nocolor` - also has `ropper --file bin --console` with a `patch` cmd.
- `bsdiff` / `xdelta3` - distribute a patch instead of a 30 MB binary.

## References

- Ghidra help: "Patch Instruction" and "Export Program" dialogs.
- radare2 book, chapter "Write / Patching binaries" (`w` command family).
- LIEF documentation, `lief.ELF.Binary.add` for segment injection.
