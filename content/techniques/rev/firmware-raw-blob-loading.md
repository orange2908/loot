---
title: "Firmware and Raw Blobs - Extraction, Architecture ID, Base Address"
category: rev
subcategory: firmware
type: technique
tags: [firmware, embedded, binwalk, squashfs, jffs2, ubifs, raw-binary, base-address, load-address, cortex-m, vector-table, arm, thumb, mips, architecture-identification, ghidra, radare2, cpu-rec, rbasefind]
difficulty: hard
summary: "Carve the filesystem out of a firmware image, identify the architecture of a headerless blob, and find its load base with a pointer histogram."
when_to_use:
  - "You have a .bin/.img dump with no ELF or PE header"
  - "binwalk found a squashfs/jffs2/ubifs filesystem inside a firmware update file"
  - "Ghidra asks for a processor and a base address and you do not know either"
  - "The challenge is a bare-metal Cortex-M or MIPS router image"
tools: [binwalk, unsquashfs, jefferson, ubireader, ghidra, radare2, cpu_rec, rbasefind]
related: [triage-unknown-binary, packers-and-unpacking, shellcode-analysis, binary-patching, custom-vm-bytecode]
---

## TL;DR

Three questions, in order: what is *inside* the image (binwalk + filesystem extraction),
what *architecture* is the headerless part (opcode signatures / `cpu_rec`), and where is it
*loaded* (pointer histogram or the Cortex-M vector table). Get the base address right and
the disassembler does the rest; get it wrong and every string reference is garbage.

## Step 1 - what is in the image?

```sh
# Signature scan: what does the file contain and where
binwalk firmware.bin
# Entropy: flat 8.0 regions are compressed/encrypted; steps mark boundaries
binwalk -E firmware.bin
# Extract everything it recognises, recursively (-M), into _firmware.bin.extracted/
binwalk -Me firmware.bin
# Extract one specific signature at one offset
binwalk --dd='.*' --offset=0x120000 firmware.bin
# Raw carve when binwalk is being unhelpful
dd if=firmware.bin of=payload.bin bs=1 skip=$((0x120000)) count=$((0x400000))
```

Caveats: `binwalk -e` refuses some extractions when run as root (it warns about
`--run-as`), extraction depends on external tools being installed (`sasquatch`, `jefferson`,
`ubi_reader`, `cramfsck`, `7z`), and false positives are common - a "LZMA compressed data"
hit at a random offset is usually noise. Verify by checking that the extracted output is
sane, not by trusting the signature.

```sh
# Typical layout of a router image
#   0x00000  uImage header (magic 27 05 19 56) + gzip/LZMA kernel
#   0x180000 squashfs root filesystem (magic hsqs / sqsh)
#   0x7f0000 NVRAM / config / jffs2 overlay

# Filesystems
unsquashfs -d rootfs squashfs.bin              # standard squashfs
sasquatch -d rootfs squashfs.bin               # vendor-patched squashfs variants
jefferson -d jffs2_root jffs2.bin              # jffs2
ubireader_extract_files -o ubi_out ubi.img     # ubifs
cramfsck -x cramfs_root cramfs.bin             # cramfs
7z x romfs.bin                                 # romfs, cpio, tar, zip
file rootfs/bin/busybox                        # <- this names the architecture for free
```

Once you have a root filesystem, you usually do **not** need raw-blob techniques: the
binaries are ELF and `file` tells you everything. Check `/etc/passwd`, `/etc/shadow`,
`/www/`, and any `/bin/*` binary that is not busybox.

## Step 2 - identify the architecture of a headerless blob

```sh
# binwalk's opcode scanner: looks for architecture-specific instruction signatures
binwalk -A firmware.bin | head -40
# cpu_rec (a binwalk module / standalone): statistical architecture identification
python3 cpu_rec.py firmware.bin
# Try a disassembly and eyeball how sane it looks
rasm2 -a arm -b 32 -d "$(xxd -p -l 64 firmware.bin | tr -d '\n')"
objdump -D -b binary -m arm -EL firmware.bin | head -40
objdump -D -b binary -m mips -EB firmware.bin | head -40
```

Prologue signatures worth grepping for:

| Architecture | Typical prologue | Bytes (LE unless noted) |
|---|---|---|
| ARM32 (ARM mode) | `push {r4-r7, lr}` / `stmfd sp!,{...}` | `f0 4? 2d e9` |
| ARM32 (Thumb) | `push {r4-r7, lr}` | `b5 f0` / `??b5` (`0xB5xx`) |
| AArch64 | `stp x29, x30, [sp, #-0x10]!` | `fd 7b bf a9` |
| AArch64 | `sub sp, sp, #N` | `ff ?? ?? d1` |
| MIPS (BE) | `addiu sp, sp, -N` | `27 bd ff ??` |
| MIPS (LE) | same, byte-swapped | `?? ff bd 27` |
| x86 | `push ebp; mov ebp, esp` | `55 8b ec` |
| x86-64 | `push rbp; mov rbp, rsp` | `55 48 89 e5` |
| PowerPC (BE) | `stwu r1, -N(r1)` | `94 21 ff ??` |
| SPARC | `save %sp, -N, %sp` | `9d e3 bf ??` |
| RISC-V | `addi sp, sp, -N` | `?? ?? 01 11` patterns |
| SuperH | `mov.l r14, @-r15` | `2f e6` |

Endianness tells: a big-endian MIPS image has lots of `0x27bdff??` and strings are still
ASCII; look at 32-bit words that should be small numbers (lengths, counters) and see which
byte order makes them small.

```python
#!/usr/bin/env python3
"""archguess.py - guess the architecture of a raw blob from prologue frequencies.

Counts architecture-specific function-prologue byte patterns and ranks them.
Heuristic, not proof - always confirm by disassembling.

Usage: python3 archguess.py firmware.bin
"""
import re
import sys

# (label, compiled regex over raw bytes, weight)
SIGNATURES = [
    ("arm32-le (ARM mode, stmfd/push)", re.compile(rb"[\x00-\xff]\x40\x2d\xe9"), 3),
    ("arm32-le (bx lr)", re.compile(rb"\x1e\xff\x2f\xe1"), 2),
    ("arm32-be (stmfd)", re.compile(rb"\xe9\x2d\x40[\x00-\xff]"), 3),
    ("thumb (push {..,lr})", re.compile(rb"[\x00-\xff]\xb5"), 1),
    ("thumb (pop {..,pc})", re.compile(rb"[\x00-\xff]\xbd"), 1),
    ("aarch64 (stp x29,x30,[sp,#-16]!)", re.compile(rb"\xfd\x7b\xbf\xa9"), 4),
    ("aarch64 (ret)", re.compile(rb"\xc0\x03\x5f\xd6"), 3),
    ("mips-be (addiu sp,sp,-N)", re.compile(rb"\x27\xbd\xff[\x00-\xff]"), 4),
    ("mips-le (addiu sp,sp,-N)", re.compile(rb"[\x00-\xff]\xff\xbd\x27"), 4),
    ("mips (jr ra)", re.compile(rb"\x03\xe0\x00\x08"), 3),
    ("x86 (push ebp; mov ebp,esp)", re.compile(rb"\x55\x8b\xec"), 3),
    ("x86-64 (push rbp; mov rbp,rsp)", re.compile(rb"\x55\x48\x89\xe5"), 4),
    ("x86 (ret)", re.compile(rb"\xc3"), 0),
    ("ppc-be (stwu r1,-N(r1))", re.compile(rb"\x94\x21\xff[\x00-\xff]"), 4),
    ("ppc-be (blr)", re.compile(rb"\x4e\x80\x00\x20"), 3),
    ("sparc (save %sp)", re.compile(rb"\x9d\xe3\xbf[\x00-\xff]"), 4),
    ("superh (mov.l r14,@-r15)", re.compile(rb"\x2f\xe6"), 2),
]


def guess(data: bytes) -> list[tuple[str, int, int]]:
    scored = []
    for label, pattern, weight in SIGNATURES:
        hits = len(pattern.findall(data))
        scored.append((label, hits, hits * weight))
    scored.sort(key=lambda row: row[2], reverse=True)
    return scored


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: archguess.py <blob>")
        return 1
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
    print(f"[*] {len(data)} bytes")
    print(f"{'signature':<38} {'hits':>7} {'score':>7}")
    for label, hits, score in guess(data):
        if hits:
            print(f"{label:<38} {hits:>7} {score:>7}")
    print("\n[!] heuristic only - confirm with: objdump -D -b binary -m <arch> <blob>")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # self-test: an aarch64 prologue + ret must rank aarch64 first
        sample = (b"\xfd\x7b\xbf\xa9" * 20) + (b"\xc0\x03\x5f\xd6" * 20) + b"\x00" * 200
        top = guess(sample)[0][0]
        assert "aarch64" in top, top
        print("[+] archguess self-test OK (detected:", top + ")")
        raise SystemExit(0)
    raise SystemExit(main())
```

## Step 3 - find the load base address

This is the crux. A raw blob contains absolute pointers (string references, jump tables,
vector tables). If you load it at the right base, those pointers land inside the image; at
any other base they point nowhere. So: try every plausible base and score it.

### The pointer histogram

```python
#!/usr/bin/env python3
"""basefind.py - find the load base of a raw firmware blob by pointer histogram.

Idea: collect every aligned 32-bit word that looks like a pointer. For a candidate base B,
a word W is "valid" if B <= W < B + len(image). The base that validates the most words is
almost always correct.

Two modes:
  * scan  - try bases on a grid (default 0x1000 granularity over a plausible range)
  * infer - derive candidates directly from the pointer values themselves (fast + precise)

Usage:
    python3 basefind.py firmware.bin
    python3 basefind.py firmware.bin --endian big --align 0x1000 --top 15
"""
import argparse
import collections
import struct
import sys


def words(data: bytes, endian: str) -> list[int]:
    """Every aligned 32-bit word in the image."""
    fmt = "<I" if endian == "little" else ">I"
    n = len(data) // 4
    return list(struct.unpack(f"{'<' if endian == 'little' else '>'}{n}I", data[:n * 4])) \
        if n else []


def string_offsets(data: bytes, minlen: int = 6) -> list[int]:
    """Offsets of NUL-terminated printable strings - the targets pointers usually have."""
    out = []
    start = None
    for i, byte in enumerate(data):
        if 0x20 <= byte < 0x7F:
            if start is None:
                start = i
        else:
            if start is not None and byte == 0 and i - start >= minlen:
                out.append(start)
            start = None
    return out


def score_base(word_counts: collections.Counter, base: int, size: int) -> int:
    """How many distinct pointer values fall inside [base, base+size)."""
    total = 0
    for value, count in word_counts.items():
        if base <= value < base + size:
            total += count
    return total


def infer_candidates(word_counts: collections.Counter, str_offs: list[int],
                     align: int, size: int) -> collections.Counter:
    """Candidate bases implied by (pointer - string_offset) pairs.

    If word W points at the string that lives at file offset O, the base is W - O.
    Counting those differences concentrates mass on the true base.
    """
    votes: collections.Counter = collections.Counter()
    str_set = set(str_offs)
    for value in word_counts:
        for off in str_set:
            cand = value - off
            if cand < 0 or cand % align:
                continue
            votes[cand] += 1
    # keep only bases that also make many other pointers land in range
    return votes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("blob")
    parser.add_argument("--endian", choices=("little", "big"), default="little")
    parser.add_argument("--align", type=lambda s: int(s, 0), default=0x1000)
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--max-base", type=lambda s: int(s, 0), default=0xFFFF0000)
    args = parser.parse_args()

    with open(args.blob, "rb") as fh:
        data = fh.read()
    size = len(data)
    print(f"[*] {args.blob}: {size} bytes, {args.endian}-endian, align {args.align:#x}")

    all_words = words(data, args.endian)
    # Filter obvious non-pointers: 0, small ints, 0xffffffff, and unaligned values
    pointers = [w for w in all_words if 0x400 < w < args.max_base and w != 0xFFFFFFFF]
    counts = collections.Counter(pointers)
    print(f"[*] {len(pointers)} pointer-like words, {len(counts)} distinct")

    str_offs = string_offsets(data)
    print(f"[*] {len(str_offs)} candidate strings")

    votes = infer_candidates(counts, str_offs[:2000], args.align, size)
    print(f"[*] {len(votes)} candidate bases from string correlation")

    ranked = []
    for cand, vote in votes.most_common(400):
        ranked.append((score_base(counts, cand, size), vote, cand))
    ranked.sort(reverse=True)

    print(f"\n{'base':>12} {'in-range ptrs':>14} {'string votes':>13}")
    for score, vote, cand in ranked[:args.top]:
        print(f"{cand:>#12x} {score:>14} {vote:>13}")

    if ranked:
        best = ranked[0][2]
        print(f"\n[+] best guess: {best:#x}")
        print(f"    ghidra: Raw Binary loader, base address {best:#x}")
        print(f"    radare2: r2 -m {best:#x} -a <arch> -b <bits> {args.blob}")
    else:
        print("\n[-] nothing conclusive: try the other endianness, or the "
              "Cortex-M vector-table method, or a coarser --align")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # self-test: build a fake image whose pointers assume base 0x08000000
        BASE = 0x08000000
        blob = bytearray(b"\x00" * 0x400)
        text = b"firmware version 1.2.3\x00"
        str_off = len(blob)
        blob += text
        blob += b"\x00" * ((-len(blob)) % 4)
        for _ in range(50):                     # a table of pointers to that string
            blob += struct.pack("<I", BASE + str_off)
        blob += b"\x00" * 0x200
        counts = collections.Counter(words(bytes(blob), "little"))
        assert score_base(counts, BASE, len(blob)) >= 50
        print(f"[+] basefind self-test OK (base {BASE:#x} scores "
              f"{score_base(counts, BASE, len(blob))})")
        raise SystemExit(0)
    raise SystemExit(main())
```

Existing implementations of the same idea: `rbasefind` (Rust, fast), `basefind.py` (from
the Ghidra/IDA community), and `binbloom` (also detects endianness and the UDS-style base).
Run one of them if it is installed; the script above exists so you understand the method and
can adapt the heuristics.

### Cortex-M: the vector table gives you the base for free

An ARM Cortex-M image starts with the exception vector table:

| Offset | Contents |
|---|---|
| `0x00` | initial Main Stack Pointer - a **RAM** address, typically `0x2000xxxx` |
| `0x04` | Reset handler - a **flash** address with the Thumb bit set, so it is **odd** |
| `0x08` | NMI handler |
| `0x0C` | HardFault handler |
| ... | a run of similar odd addresses |

```sh
# Read the first 16 words - if word0 looks like 0x2000xxxx and word1..n are odd
# addresses clustered in a narrow range, you have a Cortex-M image.
xxd -e -g4 -l 64 firmware.bin
```

If the reset vector is `0x08000245` then the image is loaded at `0x08000000` (STM32 flash),
because the handler must live inside the image and the image starts at a 0x1000/0x10000
boundary just below the smallest vector. Common bases: `0x08000000` (STM32),
`0x00000000` (many Cortex-M0), `0x1000` offsets for bootloader-reserved space,
`0x10000000` (some NXP/Kinetis), `0x00200000` (SAM).

## Step 4 - load it

### Ghidra

1. `File > Import File`, set **Format: Raw Binary**.
2. Click **Language...** and pick the processor, e.g.
   `ARM:LE:32:Cortex` (Cortex-M, Thumb), `ARM:LE:32:v7`, `AARCH64:LE:64:v8A`,
   `MIPS:BE:32:default`, `PowerPC:BE:32:default`, `x86:LE:32:default`.
3. Click **Options...** and set **Base Address** to what you found.
4. After import, open **Window > Memory Map** and:
   - confirm the single block covers the image at the right address,
   - add blocks for **RAM** (e.g. `0x20000000`, size 0x20000, RW, uninitialised) and for
     **MMIO peripherals** (`0x40000000`) so pointer targets resolve instead of showing as
     unmapped. Use the "Add Memory Block" button, tick *Read*/*Write*, untick *Initialized*.
5. Define the vector table: go to the base address, press `D` to clear, then apply a
   `pointer` data type repeatedly (or select 64 bytes and `Data > pointer`). Ghidra will
   create functions at the targets. For Cortex-M, clear the Thumb bit mentally - Ghidra's
   Cortex language handles odd addresses by marking TMode.
6. Set the **TMode register** for Thumb-only code if functions disassemble as ARM:
   select the range, `Ctrl+Alt+T` / right-click `Processor Options`, or use the
   `SetTModeScript` community script.
7. Run **Analysis > Auto Analyze** *after* the memory map is right, not before.

### radare2 / rizin

```sh
# -m sets the map address, -a arch, -b bits, -e cfg.bigendian for BE targets
r2 -a arm -b 16 -m 0x08000000 firmware.bin      # Thumb
r2 -a arm -b 32 -m 0x00000000 firmware.bin      # ARM mode
r2 -a mips -b 32 -e cfg.bigendian=true -m 0x80000000 firmware.bin
# inside r2:
#   e asm.cpu=cortex
#   aaa           ; analyse
#   afl           ; list functions
#   s 0x08000004; pd 1    ; read the reset vector
```

### IDA

`File > Open`, choose **Binary file**, then set the processor type
(`ARM: ARMv7-M`, `MIPS: mipsb`, ...). IDA then asks for the **Loading segment** and
**Loading offset** - enter your base. Afterwards, `Edit > Segments > Create segment` for RAM
and MMIO, and `Options > General > Analysis > Reanalyze program`.

## Step 5 - what to look for next

```sh
# Strings are the map of an embedded image
strings -a -n 6 firmware.bin | grep -iE 'password|flag|key|admin|login|uart|version|%s'
# Identify the RTOS / libc
strings -a firmware.bin | grep -iE 'freertos|vxworks|threadx|uclibc|busybox|linux version'
# VxWorks images often embed a symbol table: look for runs of
#   <name string> <address> <type> triplets - tools like vxhunter recover them
# U-Boot environment blocks: `bootargs=`, `bootcmd=` strings mark the config area
strings -a firmware.bin | grep -E '^boot(args|cmd)='
```

Then apply the ordinary playbook: find the flag comparison, the UART menu handler, or the
authentication routine, and treat it as a normal crackme (`crackme-patterns`).

## Variants & pitfalls

- **Wrong endianness** makes every pointer nonsense. If basefind finds nothing, flip it.
- **Multiple images in one file** (bootloader at 0, application at 0x8000) need different
  bases. Split the file and treat each separately.
- **Compressed kernel**: the `uImage` payload is gzip/LZMA. Decompress before analysing
  (`binwalk -Me`, or `dd` past the 64-byte uImage header and `gunzip`).
- **Encrypted firmware**: uniformly 8.0 entropy with no recognisable structure. Look for the
  update-verification code in an earlier bootloader stage, or for a key in a companion file.
- **Thumb vs ARM confusion**: if half your functions look insane, you have the wrong mode.
  On Cortex-M everything is Thumb.
- **Overlapping RAM images**: code that is copied from flash to RAM at startup runs at a
  *different* address than it is stored. Look for a memcpy-like loop at reset and create a
  second Ghidra block for the RAM copy.
- **binwalk false positives**: a "JFFS2 filesystem" hit inside compressed data is noise.
  Check that the extracted output has sane structure.
- **Do not analyse before fixing the memory map** - Ghidra caches bad analysis, and
  re-running auto-analysis after a base change does not fully undo it. Re-import instead.

## Tools

- `binwalk` (signature scan, entropy, `-A` opcode scan, recursive extraction).
- `unsquashfs` / `sasquatch`, `jefferson`, `ubi_reader`, `cramfsck` - filesystems.
- `cpu_rec` - statistical architecture identification.
- `rbasefind` / `binbloom` / `basefind.py` - base address search.
- `Ghidra` Raw Binary loader + Memory Map; `radare2 -m`; IDA binary loader.
- `vxhunter` - VxWorks symbol table recovery.
- `flashrom` / `binwalk -E` - when you dumped the chip yourself.

## References

- ARMv7-M Architecture Reference Manual: the exception vector table layout (initial SP at
  offset 0, reset vector at offset 4 with bit 0 set for Thumb).
- binwalk documentation for `-A`, `-E`, `-M` and the extraction rules file.
- Ghidra help: "Importing Files" -> Raw Binary, and "Memory Map" for adding blocks.
