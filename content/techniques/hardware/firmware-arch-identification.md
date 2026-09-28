---
title: "Unknown Blob - Identifying Architecture, Endianness and Load Address"
category: hardware
subcategory: firmware
type: technique
tags: [binwalk, cpu-rec, binbloom, capstone, radare2, ghidra, arch-detection, endianness, load-address, vector-table, reset-vector, arm, mips, thumb, isfdb, entropy]
difficulty: hard
summary: "Work out which CPU a headerless firmware blob targets, its endianness, and where it is mapped, so a disassembler produces real code."
when_to_use:
  - "binwalk found no filesystem and the blob is bare-metal firmware"
  - "Ghidra produces garbage because the base address is wrong"
  - "You need to know if it is ARM, Thumb, MIPS, or something exotic"
tools: [binwalk, cpu_rec, binbloom, radare2, ghidra, capstone, python]
related: [firmware-extraction, mcu-reversing, firmware-emulation, jtag-swd]
---

## TL;DR

Three unknowns: **architecture**, **endianness**, **load address**. Solve them in that
order. Architecture comes from statistical signatures (`cpu_rec`) or from a recognisable
vector table. Endianness comes from how the first words look. Load address comes from
making absolute pointers inside the blob point at plausible things - either the ARM reset
vector, or the offset that maximises valid string-pointer hits (`binbloom`).

## Recognise it

- `binwalk` finds nothing, or only a couple of compressed blobs.
- Entropy is moderate (5.5-7.0): code, not compressed data.
- `strings` shows a compiler banner (`GCC: (GNU) 4.8.5`), an RTOS name
  (`FreeRTOS`, `ThreadX`, `uC/OS`, `Nucleus`, `VxWorks`), or an SDK tag
  (`ESP-IDF`, `nRF5 SDK`, `STM32Cube`).
- Long runs of repeating 4-byte patterns near offset 0 (a vector table).
- Disassembling at offset 0 with the wrong arch gives `undefined` everywhere.

## Theory

### Architecture fingerprints

| Signal | Architecture |
|---|---|
| `0x0000000?` words at 0x0 that all look like `0x0800xxxx` or `0x0000xxxx` with bit0 set | ARM Cortex-M (Thumb vector table) |
| First word is a plausible SP (`0x2000xxxx` on STM32), second is a PC with bit 0 = 1 | Cortex-M confirmed |
| Many `0xE?` high nibbles in 4-byte words | ARM (A32) condition field `AL = 0xE` |
| `0x3C1C` / `0x27BD` word starts, MIPS `addiu sp,sp,-N` = `0x27BDxxxx` | MIPS |
| `0x9421` prologue (`stwu r1,-N(r1)`) | PowerPC |
| `0x55 0x89 0xE5` / `0x48 0x89 0xE5` | x86 / x86-64 |
| `0x1141` / `0x1101` (`addi sp,sp,-N` compressed) | RISC-V |
| `0x??20 0x4E56` | m68k (`link a6`) |
| Lots of `0x0800`-ish absolute addresses | STM32 internal flash mapped at 0x08000000 |
| `0xE9` / `0xEA` opcodes with 24-bit offsets | ARM branch instructions |
| `Xtensa` strings / `ESP32`/`ESP8266` markers | Xtensa LX6/LX106 |
| `0x1234` `AVR` fuses / `.hex` text file | AVR |

### Endianness test

Take the first 256 4-byte words. Interpret both ways. The correct endianness usually gives:

- small, clustered values (a vector table of nearby addresses),
- values within the blob's size or within a plausible flash window,
- readable ASCII when a word is a pointer into a string table.

Also: ASCII strings are endianness-independent, but 16-bit Unicode and length-prefixed
structures are not.

### Load address (base address) recovery

Firmware is compiled for a fixed base. Absolute pointers inside it are
`base + offset_in_image`. So:

1. Collect every 4-byte word that could be a pointer (aligned, within a plausible range).
2. Collect the offsets of every ASCII string in the blob.
3. For each candidate base `B` (step 0x1000 over the plausible range), count how many
   pointers satisfy `pointer - B` == some string offset.
4. The base with the highest hit count is almost always correct.

`binbloom` implements exactly this. For Cortex-M there is a shortcut: the reset vector
(word at +4) points into the image, so `base = (reset_vector & ~1) - offset_of_reset_code`,
and in practice the base is simply the top bits of the vector-table entries
(`0x08000000`, `0x00000000`, `0x1000`...).

### Common base addresses

| Platform | Flash base |
|---|---|
| STM32 (internal flash) | `0x08000000` |
| Nordic nRF51/52 | `0x00000000` |
| NXP LPC / Kinetis | `0x00000000` |
| ESP32 (irom) | `0x400D0000` |
| ESP8266 (irom) | `0x40200000` |
| TI CC2xxx / MSP432 | `0x00000000` |
| Atmel SAM | `0x00400000` |
| MIPS (big routers, kseg0) | `0x80000000` |
| MIPS boot vector | `0xBFC00000` |
| ARM Linux kernel | `0xC0008000` (32-bit) |
| Renesas RX | `0xFFF00000` |

## Attack

1. `binwalk -E` for entropy, `strings` for a toolchain/RTOS banner.
2. `cpu_rec` over the blob and over sliding windows (a blob can mix architectures).
3. Check for a Cortex-M vector table at offset 0 (the cheapest, highest-confidence test).
4. If not Cortex-M, disassemble the first 0x200 bytes under each candidate arch and score
   how many instructions decode validly (script below).
5. Recover the base with `binbloom`, or the string-pointer correlation script.
6. Load into Ghidra with the language and base address, and check that
   function starts line up and strings get referenced.
7. Iterate: if cross-references look wrong, the base is off.

## Code

```python
#!/usr/bin/env python3
"""blobid.py - identify architecture, endianness and load address of a raw firmware blob.

Three independent techniques:
  1. Cortex-M vector table detection (exact, when it applies)
  2. instruction-validity scoring across candidate architectures (needs capstone)
  3. pointer/string correlation to recover the load base (pure stdlib)

Usage:
  python3 blobid.py firmware.bin
  python3 blobid.py firmware.bin --base-scan 0x00000000 0x40000000 0x1000
"""
from __future__ import annotations

import collections
import math
import re
import struct
import sys

STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")

CORTEX_M_SP_RANGES = [
    (0x20000000, 0x20100000, "SRAM (STM32/nRF/most Cortex-M)"),
    (0x10000000, 0x10100000, "SRAM (LPC / some NXP)"),
    (0x1FFF0000, 0x20000000, "SRAM (Kinetis low alias)"),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------
# 1. Cortex-M vector table
# --------------------------------------------------------------------------
def check_cortex_m(data: bytes) -> dict | None:
    if len(data) < 64:
        return None
    words = struct.unpack("<16I", data[:64])
    sp, reset = words[0], words[1]

    sram = None
    for lo, hi, name in CORTEX_M_SP_RANGES:
        if lo <= sp < hi:
            sram = name
            break
    if sram is None:
        return None
    if reset & 1 == 0:          # Cortex-M handlers are Thumb: bit 0 must be set
        return None

    # every non-zero handler must be Thumb and share a plausible flash region
    handlers = [w for w in words[1:] if w != 0]
    if not handlers or not all(h & 1 for h in handlers):
        return None

    base_guess = (reset & 0xFFF00000)
    return {
        "arch": "ARM Cortex-M (Thumb)",
        "endian": "little",
        "initial_sp": sp,
        "sram": sram,
        "reset_vector": reset,
        "handlers": len(handlers),
        "base_guess": base_guess,
    }


# --------------------------------------------------------------------------
# 2. instruction validity scoring
# --------------------------------------------------------------------------
CANDIDATES = [
    ("arm-le", "CS_ARCH_ARM", "CS_MODE_ARM", "little"),
    ("arm-be", "CS_ARCH_ARM", "CS_MODE_ARM|CS_MODE_BIG_ENDIAN", "big"),
    ("thumb-le", "CS_ARCH_ARM", "CS_MODE_THUMB", "little"),
    ("arm64", "CS_ARCH_ARM64", "CS_MODE_ARM", "little"),
    ("mips32-be", "CS_ARCH_MIPS", "CS_MODE_MIPS32|CS_MODE_BIG_ENDIAN", "big"),
    ("mips32-le", "CS_ARCH_MIPS", "CS_MODE_MIPS32", "little"),
    ("ppc-be", "CS_ARCH_PPC", "CS_MODE_32|CS_MODE_BIG_ENDIAN", "big"),
    ("x86-32", "CS_ARCH_X86", "CS_MODE_32", "little"),
    ("x86-64", "CS_ARCH_X86", "CS_MODE_64", "little"),
    ("riscv32", "CS_ARCH_RISCV", "CS_MODE_RISCV32", "little"),
    ("sparc-be", "CS_ARCH_SPARC", "CS_MODE_BIG_ENDIAN", "big"),
]


def score_architectures(data: bytes, window: int = 0x800) -> list[tuple[str, float, int]]:
    try:
        import capstone  # type: ignore
    except ImportError:
        print("[!] capstone not installed - skipping instruction scoring "
              "(pip install capstone)", file=sys.stderr)
        return []

    chunk = data[:window]
    results = []
    for name, arch_name, mode_expr, _endian in CANDIDATES:
        arch = getattr(capstone, arch_name, None)
        if arch is None:
            continue
        mode = 0
        ok = True
        for part in mode_expr.split("|"):
            val = getattr(capstone, part, None)
            if val is None:
                ok = False
                break
            mode |= val
        if not ok:
            continue
        try:
            md = capstone.Cs(arch, mode)
            md.skipdata = True
            insns = list(md.disasm(chunk, 0))
        except Exception:                      # noqa: BLE001 - capstone raises broadly
            continue
        if not insns:
            continue
        bad = sum(1 for i in insns if i.mnemonic in ("", ".byte", "bad"))
        covered = sum(i.size for i in insns if i.mnemonic not in ("", ".byte", "bad"))
        score = covered / max(1, len(chunk))
        results.append((name, score, len(insns) - bad))
    results.sort(key=lambda t: -t[1])
    return results


# --------------------------------------------------------------------------
# 3. load-address recovery by pointer/string correlation
# --------------------------------------------------------------------------
def find_strings(data: bytes) -> set[int]:
    return {m.start() for m in STRING_RE.finditer(data)}


def candidate_pointers(data: bytes, little: bool = True) -> list[int]:
    fmt = "<I" if little else ">I"
    out = []
    for off in range(0, len(data) - 4, 4):
        val = struct.unpack_from(fmt, data, off)[0]
        if 0x1000 <= val < 0xFFFFFFF0:
            out.append(val)
    return out


def guess_base(data: bytes, lo: int = 0x00000000, hi: int = 0x40000000,
               step: int = 0x1000, little: bool = True) -> list[tuple[int, int]]:
    strings = find_strings(data)
    pointers = candidate_pointers(data, little)
    size = len(data)
    scores: collections.Counter[int] = collections.Counter()
    for p in pointers:
        # if p == base + off and off is a string offset, then base = p - off
        for off in strings:
            base = p - off
            if lo <= base <= hi and base % step == 0:
                scores[base] += 1
    # discard bases that would put the image outside a sane window
    ranked = [(b, c) for b, c in scores.most_common(10) if b + size < (1 << 32)]
    return ranked


def report(path: str, base_range: tuple[int, int, int] | None = None) -> None:
    with open(path, "rb") as fh:
        data = fh.read()
    print(f"== {path}: {len(data)} bytes, entropy {entropy(data):.3f}")

    if entropy(data) > 7.5:
        print("[!] very high entropy: compressed or encrypted, not raw code")

    print("\n-- toolchain / rtos strings --")
    wanted = (b"GCC", b"FreeRTOS", b"ThreadX", b"VxWorks", b"uC/OS", b"Nucleus",
              b"ESP-IDF", b"nRF5", b"STM32", b"Zephyr", b"Linux version", b"U-Boot",
              b"Xtensa", b"RISC-V", b"mips", b"arm-none-eabi")
    for w in wanted:
        idx = data.find(w)
        if idx >= 0:
            end = min(idx + 80, len(data))
            snippet = data[idx:end].split(b"\x00")[0]
            print(f"  0x{idx:08x}  {snippet.decode('ascii', 'replace')[:76]}")

    print("\n-- cortex-m vector table --")
    cm = check_cortex_m(data)
    if cm:
        print(f"  MATCH: {cm['arch']}")
        print(f"  initial SP  = 0x{cm['initial_sp']:08x}  ({cm['sram']})")
        print(f"  reset vector= 0x{cm['reset_vector']:08x}")
        print(f"  {cm['handlers']} non-zero thumb handlers")
        print(f"  likely load base = 0x{cm['base_guess']:08x}")
    else:
        print("  no cortex-m vector table at offset 0")

    print("\n-- instruction validity scoring (first 2 KiB) --")
    for name, score, count in score_architectures(data)[:6]:
        print(f"  {name:<12} coverage={score:6.2%}  valid_insns={count}")

    print("\n-- load base by pointer/string correlation --")
    lo, hi, step = base_range or (0x00000000, 0x40000000, 0x1000)
    for base, hits in guess_base(data, lo, hi, step)[:8]:
        print(f"  0x{base:08x}  {hits} pointer/string agreements")
    print("\n  (cross-check the winner in ghidra: strings must gain xrefs)")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    rng = None
    if "--base-scan" in argv:
        i = argv.index("--base-scan")
        rng = (int(argv[i + 1], 0), int(argv[i + 2], 0), int(argv[i + 3], 0))
    report(argv[1], rng)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # synthesise a cortex-m image with a vector table and a pointer to a string
        BASE = 0x08000000
        body = bytearray(0x400)
        strings_at = 0x200
        msg = b"firmware version 1.2.3 build ok\x00"
        body[strings_at:strings_at + len(msg)] = msg
        vec = struct.pack("<16I", 0x20005000, BASE + 0x101, BASE + 0x121, BASE + 0x131,
                          *([BASE + 0x141] * 12))
        body[0:64] = vec
        struct.pack_into("<I", body, 0x180, BASE + strings_at)   # a pointer to the string
        struct.pack_into("<I", body, 0x184, BASE + strings_at + 8)
        blob = bytes(body)

        cm = check_cortex_m(blob)
        assert cm is not None, "vector table not detected"
        assert cm["initial_sp"] == 0x20005000
        assert cm["base_guess"] == 0x08000000, hex(cm["base_guess"])

        bases = guess_base(blob, 0x00000000, 0x20000000, 0x1000)
        assert bases, "no base candidates"
        assert bases[0][0] == BASE, [(hex(b), c) for b, c in bases[:3]]

        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "fw.bin")
            with open(p, "wb") as fh:
                fh.write(blob)
            report(p, (0x00000000, 0x20000000, 0x1000))
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Tool commands

```bash
# statistical architecture classifier over sliding windows
cpu_rec.py firmware.bin
binwalk -% firmware.bin                       # binwalk's entropy/opcode heuristic
binwalk -Y firmware.bin                       # capstone-based opcode scan
binwalk -A firmware.bin                       # scan for known function prologues

# base address recovery
binbloom -f firmware.bin -e l                 # little endian
binbloom -f firmware.bin -e b                 # big endian
binbloom -f firmware.bin -t base              # base address mode

# radare2: try a configuration and see if it decodes
r2 -a arm -b 16 -e asm.cpu=cortex -m 0x08000000 firmware.bin
# inside r2:  aaa ; afl ; pd 40 ; izz ; /a mov r0
r2 -a mips -b 32 -e cfg.bigendian=true -m 0x80000000 firmware.bin

# quick manual decode check with objdump
arm-none-eabi-objdump -D -b binary -m arm -M force-thumb firmware.bin | head -60
mips-linux-gnu-objdump -D -b binary -m mips -EB firmware.bin | head -60

# ghidra headless with an explicit language and base
analyzeHeadless /tmp/proj fw -import firmware.bin \
  -processor ARM:LE:32:Cortex -loader BinaryLoader -loader-baseAddr 0x08000000
analyzeHeadless /tmp/proj fw -import firmware.bin \
  -processor MIPS:BE:32:default -loader BinaryLoader -loader-baseAddr 0x80000000

# vector table by eye (cortex-m): SP then handler addresses with bit 0 set
xxd -e -g 4 -l 64 firmware.bin
```

## Variants & pitfalls

- **Mixed architectures in one image** - a bootloader in ARM and an application in Thumb,
  or an ARM host plus a DSP blob. Run `cpu_rec` with a sliding window, not once.
- **Thumb vs ARM** - Cortex-M is Thumb-only; Cortex-A firmware mixes both. In Ghidra set
  the `TMode` register to 1 on Thumb functions.
- **Base off by the header size** - if you kept a 0x40-byte vendor header, every pointer is
  0x40 too high. Strip headers before base recovery.
- **The image is position independent** (some RTOS apps) - there are no absolute pointers,
  so correlation finds nothing. Use the vector table or the linker map if shipped.
- **ESP32/ESP8266** images have their own header (`0xE9` magic) with segment load addresses
  - read it instead of guessing (`esptool.py image_info`).
- **A wrong-but-plausible base** still produces code; verify by checking that string
  references resolve and that function prologues land on 2/4-byte boundaries.

## Tools

- `cpu_rec` - statistical architecture identification (a binwalk plugin too).
- `binbloom` - base-address and endianness recovery.
- `binwalk -A/-Y/-%` - opcode and prologue scanning.
- `capstone` / `radare2` / `rizin` - quick decode trials.
- `ghidra` with `-loader BinaryLoader -loader-baseAddr`.
- `esptool.py image_info`, `mkimage -l`, `dtc` - when a header does exist.

## References

- cpu_rec project documentation on its corpus-based classification method.
- binbloom project documentation on base-address recovery heuristics.
- ARM documentation on the Cortex-M vector table layout and Thumb bit conventions.
