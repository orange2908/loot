---
title: "Microcontroller Reversing - AVR, PIC, STM32 and ESP32"
category: hardware
subcategory: mcu
type: technique
tags: [avr, avrdude, pic, stm32, esp32, esp8266, esptool, fuses, lock-bits, readout-protection, ghidra, avr-objdump, intel-hex, eeprom, bootloader, svd, peripherals]
difficulty: hard
summary: "Read a microcontroller's flash and fuses, identify the memory map, and reverse the firmware with the right peripheral layout loaded."
when_to_use:
  - "The challenge ships a .hex/.elf/.bin for a specific MCU"
  - "You have a physical board with an AVR/PIC/STM32/ESP chip"
  - "You need to know whether the part is read-protected before trying to dump it"
tools: [avrdude, esptool, openocd, ghidra, radare2, srec_cat, minipro, python]
related: [firmware-arch-identification, jtag-swd, fault-injection-glitching, uart-serial]
---

## TL;DR

Identify the exact part number from the package marking, look up its flash base, RAM base
and peripheral base, then dump: `avrdude -U flash:r:` for AVR, `esptool.py read_flash`
for ESP, OpenOCD/`dump_image` for STM32 (see `jtag-swd`), `minipro`/PICkit for PIC.
Check the lock/fuse/eFuse bits first - a protected part returns zeros and you have
wasted an hour. In Ghidra, load the correct processor **and** an SVD file so peripheral
registers get names.

## Recognise it

- A `.hex` (Intel HEX, ASCII lines starting `:`), `.eep`, `.elf`, or a raw `.bin`.
- Package markings: `ATMEGA328P-PU`, `PIC16F877A`, `STM32F103C8T6`, `ESP32-WROOM-32`,
  `nRF52832`, `CH32V003`.
- `file firmware.elf` -> `ELF 32-bit LSB executable, Atmel AVR 8-bit` or
  `ARM, EABI5`, or `Tensilica Xtensa`.
- An ESP image starts with `0xE9` followed by a segment count.

## Theory

### Family cheat facts

| Family | Core | Flash base | RAM base | Dump tool | Protection |
|---|---|---|---|---|---|
| AVR (ATmega/ATtiny) | 8-bit Harvard AVR | 0x0000 (word addressed) | 0x0100 (data space) | `avrdude` (ISP/UPDI/HVPP) | lock bits LB1/LB2 |
| AVR (ATmega32U4 etc.) | same + USB | 0x0000 | 0x0100 | `avrdude -c avr109` (DFU/Caterina) | lock bits |
| PIC16/18 | 8-bit PIC | 0x0000 (14/16-bit words) | 0x0000 file registers | PICkit + `minipro`/`pk2cmd` | CP config bit |
| STM32 | ARM Cortex-M | 0x08000000 | 0x20000000 | OpenOCD, ST-Link, `stm32flash` | RDP level 0/1/2 |
| nRF51/52 | Cortex-M0/M4 | 0x00000000 | 0x20000000 | OpenOCD, nrfjprog | APPROTECT |
| ESP8266 | Xtensa LX106 | 0x40200000 (irom) | 0x3FFE8000 | `esptool.py` | flash encryption (usually off) |
| ESP32 | Xtensa LX6 / RISC-V | 0x400D0000 (irom) | 0x3FFB0000 | `esptool.py` | eFuse FLASH_CRYPT, SB |
| MSP430 | MSP430 | 0x8000+ | 0x0200 | `mspdebug` | JTAG fuse, BSL password |
| RP2040 | Cortex-M0+ | 0x10000000 (XIP) | 0x20000000 | picotool, SWD | none by default |

AVR addresses are confusing: program memory is **word** addressed in the architecture but
`avr-objdump` shows byte addresses. Peripheral registers live in the data space
(`0x20` + I/O address for `IN`/`OUT` instructions).

### ESP image format

```
offset 0: 0xE9 magic
offset 1: segment count
offset 2: SPI mode      (0=QIO 1=QOUT 2=DIO 3=DOUT)
offset 3: SPI speed/size (high nibble = size, low nibble = frequency)
offset 4-7: entry point
then per segment: 4-byte load address, 4-byte length, data
```

`esptool.py image_info firmware.bin` prints all of it - including the per-segment load
addresses, which is exactly the base-address problem solved for free.

### Intel HEX

```
:LLAAAATT[DD...]CC
 LL = byte count, AAAA = address, TT = record type
 TT: 00 data, 01 EOF, 02 extended segment address,
     04 extended linear address (upper 16 bits), 05 start linear address
 CC = two's complement checksum of all preceding bytes
```

Convert with `srec_cat`/`objcopy` before feeding it to a disassembler.

### Fuses and lock bits (AVR)

- **Low fuse**: clock source and startup time. Setting an external crystal on a board
  with no crystal bricks ISP until you supply a clock.
- **High fuse**: `SPIEN` (never disable), `EESAVE`, `BOOTSZ`, `BOOTRST`, `WDTON`.
- **Extended fuse**: BOD level.
- **Lock bits**: `LB1:LB0 = 00` disables further programming *and* verification -
  a read returns garbage. Only a chip erase clears lock bits, and that erases flash.

## Attack

1. Read the part number; get the datasheet memory map.
2. Read fuses/lock bits/eFuses **before** attempting a flash read.
3. Dump flash and EEPROM.
4. Identify the image format (`.hex` vs raw) and convert to a flat binary.
5. Disassemble with the correct architecture and base address.
6. Load peripheral definitions (SVD for ARM, the device header for AVR) so register
   accesses read as `GPIOA->ODR` rather than `*(int*)0x40010810`.
7. Find the flag: strings first, then the UART/USB output routines, then the comparison.

## Code

### AVR

```bash
# identify and read fuses (always first)
avrdude -c usbasp -p m328p -v
avrdude -c usbasp -p m328p -U lfuse:r:-:h -U hfuse:r:-:h -U efuse:r:-:h -U lock:r:-:h

# dump flash and eeprom
avrdude -c usbasp -p m328p -U flash:r:flash.hex:i
avrdude -c usbasp -p m328p -U flash:r:flash.bin:r
avrdude -c usbasp -p m328p -U eeprom:r:eeprom.bin:r
avrdude -c usbasp -p m328p -B 10 -U flash:r:flash.bin:r     # slower clock if it fails

# other programmers
avrdude -c arduino -P /dev/ttyUSB0 -b 115200 -p m328p -U flash:r:flash.bin:r
avrdude -c avrisp2 -P usb -p m328p -U flash:r:flash.bin:r
avrdude -c jtag2updi -P /dev/ttyUSB0 -p t1614 -U flash:r:flash.bin:r     # modern tinyAVR
avrdude -c usbasp -p m328p -U flash:w:patched.hex:i           # write back

# disassemble
avr-objdump -D -m avr5 -b binary flash.bin | head -60
avr-objdump -d flash.elf
avr-objdump -s -j .eeprom flash.elf
strings -n 4 flash.bin

# hex <-> bin
srec_cat flash.hex -intel -o flash.bin -binary
srec_cat flash.bin -binary -o flash.hex -intel
avr-objcopy -I ihex -O binary flash.hex flash.bin
python3 -c "
import sys
data=bytearray()
for line in open('flash.hex'):
    line=line.strip()
    if not line.startswith(':'): continue
    n=int(line[1:3],16); addr=int(line[3:7],16); t=int(line[7:9],16)
    if t!=0: continue
    if len(data)<addr+n: data.extend(b'\xff'*(addr+n-len(data)))
    data[addr:addr+n]=bytes.fromhex(line[9:9+n*2])
open('flash.bin','wb').write(data); print(len(data),'bytes')
"
```

### ESP8266 / ESP32

```bash
# identify the chip, its mac and its flash size
esptool.py --port /dev/ttyUSB0 chip_id
esptool.py --port /dev/ttyUSB0 flash_id
esptool.py --port /dev/ttyUSB0 read_mac

# eFuses: is flash encryption or secure boot enabled? (espefuse is part of esptool)
espefuse.py --port /dev/ttyUSB0 summary

# dump the whole flash (4 MiB is the common size)
esptool.py --port /dev/ttyUSB0 --baud 921600 read_flash 0 0x400000 fulldump.bin
esptool.py --port /dev/ttyUSB0 read_flash 0x1000 0x7000 bootloader.bin
esptool.py --port /dev/ttyUSB0 read_flash 0x8000 0x1000 partitions.bin

# understand the layout
esptool.py image_info fulldump.bin
gen_esp32part.py partitions.bin                 # decode the partition table
python3 -m esptool image_info --version 2 app.bin

# the app partition usually starts at 0x10000 on esp32, 0x0 on esp8266
dd if=fulldump.bin of=app.bin bs=1 skip=$((0x10000)) count=$((0x100000))
esptool.py image_info app.bin                   # gives per-segment load addresses

# spiffs / littlefs data partitions
mkspiffs -u ./spiffs_out -b 4096 -p 256 -s 0x100000 spiffs.bin
binwalk -e fulldump.bin
strings -n 6 fulldump.bin | grep -iE 'flag|password|ssid|http' | head -30

# nvs partition (esp32 key/value store) often holds credentials
python3 nvs_tool.py nvs.bin                     # from esp-idf components/nvs_flash
strings -n 4 nvs.bin | head -40

# write back
esptool.py --port /dev/ttyUSB0 write_flash 0x10000 patched.bin
esptool.py --port /dev/ttyUSB0 erase_flash
```

### STM32

```bash
# over swd (see jtag-swd for the full story)
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; dump_image flash.bin 0x08000000 0x10000; shutdown"

# read protection level from the option bytes
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg \
  -c "init; mdw 0x1FFFF800 4; shutdown"
# RDP byte 0xA5 = level 0 (unprotected); anything else = level 1 or 2

# st-flash / stm32flash alternatives
st-info --probe
st-flash read flash.bin 0x08000000 0x10000
stm32flash -r flash.bin -S 0x08000000:65536 /dev/ttyUSB0     # via the uart bootloader
stm32flash -k /dev/ttyUSB0                                    # check readout protection
# the uart bootloader is entered by pulling BOOT0 high and resetting
```

### Python: parse Intel HEX and ESP images, summarise an MCU firmware

```python
#!/usr/bin/env python3
"""mcufw.py - parse Intel HEX and ESP firmware images, and summarise a raw MCU blob.

Pure stdlib. Turns a .hex into a flat binary with the right base address, decodes an
ESP image header (which hands you the load addresses for free), and reports strings
and reset-vector information for a raw dump.

Usage:
  python3 mcufw.py flash.hex --out flash.bin
  python3 mcufw.py app.bin --esp
  python3 mcufw.py flash.bin --avr
"""
from __future__ import annotations

import argparse
import struct
import sys

ESP_MAGIC = 0xE9
SPI_MODE = {0: "QIO", 1: "QOUT", 2: "DIO", 3: "DOUT", 4: "FAST_READ", 5: "SLOW_READ"}
SPI_SIZE = {0: "1MB", 1: "2MB", 2: "4MB", 3: "8MB", 4: "16MB", 5: "32MB"}
SPI_FREQ = {0: "40MHz", 1: "26MHz", 2: "20MHz", 0xF: "80MHz"}


def parse_ihex(text: str) -> tuple[bytes, int]:
    """Return (flat binary, base address) from Intel HEX text."""
    chunks: dict[int, int] = {}
    upper = 0
    start_addr = None
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or not line.startswith(":"):
            continue
        raw = bytes.fromhex(line[1:])
        count, addr_hi, addr_lo, rtype = raw[0], raw[1], raw[2], raw[3]
        addr = (addr_hi << 8) | addr_lo
        data = raw[4:4 + count]
        checksum = raw[4 + count]
        calc = (-sum(raw[:4 + count])) & 0xFF
        if calc != checksum:
            raise ValueError(f"line {lineno}: checksum {checksum:02x} != {calc:02x}")
        if rtype == 0x00:
            for i, b in enumerate(data):
                chunks[upper + addr + i] = b
        elif rtype == 0x01:
            break
        elif rtype == 0x02:
            upper = struct.unpack(">H", data)[0] << 4
        elif rtype == 0x04:
            upper = struct.unpack(">H", data)[0] << 16
        elif rtype == 0x05:
            start_addr = struct.unpack(">I", data)[0]
    if not chunks:
        return b"", 0
    lo, hi = min(chunks), max(chunks)
    out = bytearray(b"\xff" * (hi - lo + 1))
    for a, b in chunks.items():
        out[a - lo] = b
    if start_addr is not None:
        print(f"start linear address: 0x{start_addr:08x}", file=sys.stderr)
    return bytes(out), lo


def parse_esp_image(data: bytes) -> dict | None:
    if len(data) < 24 or data[0] != ESP_MAGIC:
        return None
    seg_count = data[1]
    mode = data[2]
    size_freq = data[3]
    entry = struct.unpack("<I", data[4:8])[0]
    info: dict = {
        "segments": seg_count,
        "spi_mode": SPI_MODE.get(mode, f"0x{mode:02x}"),
        "flash_size": SPI_SIZE.get(size_freq >> 4, f"0x{size_freq >> 4:x}"),
        "flash_freq": SPI_FREQ.get(size_freq & 0xF, f"0x{size_freq & 0xf:x}"),
        "entry": entry,
        "seg_list": [],
    }
    off = 8
    # esp32 images have an extended header; detect it by an implausible first load addr
    first = struct.unpack("<I", data[8:12])[0] if len(data) >= 12 else 0
    if not (0x3F000000 <= first <= 0x42000000 or first < 0x100000):
        off = 24
        info["extended_header"] = True
    for _ in range(seg_count):
        if off + 8 > len(data):
            break
        load, length = struct.unpack("<II", data[off:off + 8])
        off += 8
        info["seg_list"].append({"load": load, "len": length, "file_off": off})
        off += length
        if off > len(data):
            break
    return info


def strings_in(data: bytes, min_len: int = 6, limit: int = 40) -> list[str]:
    out: list[str] = []
    run = bytearray()
    for b in data:
        if 32 <= b < 127:
            run.append(b)
        else:
            if len(run) >= min_len:
                out.append(run.decode())
                if len(out) >= limit:
                    return out
            run = bytearray()
    if len(run) >= min_len:
        out.append(run.decode())
    return out


def avr_summary(data: bytes) -> None:
    """AVR interrupt vectors are rjmp/jmp instructions at the very start."""
    print("-- avr vector table (first 16 entries) --")
    for i in range(0, min(64, len(data)), 4):
        w0 = struct.unpack("<H", data[i:i + 2])[0]
        if (w0 & 0xF000) == 0xC000:                # rjmp
            offset = w0 & 0x0FFF
            if offset & 0x800:
                offset -= 0x1000
            target = (i // 2) + 1 + offset
            print(f"  vec {i//2:>2}: rjmp -> word 0x{target:04x} (byte 0x{target*2:04x})")
        elif (w0 & 0xFE0E) == 0x940C:              # jmp (32-bit)
            w1 = struct.unpack("<H", data[i + 2:i + 4])[0]
            print(f"  vec {i//4:>2}: jmp  -> word 0x{w1:04x} (byte 0x{w1*2:04x})")
    print("\n-- avr disassembly hint --")
    print("  avr-objdump -D -m avr5 -b binary flash.bin | less")


def report(path: str, as_esp: bool, as_avr: bool, out: str | None) -> int:
    with open(path, "rb") as fh:
        raw = fh.read()

    if raw[:1] == b":" or path.lower().endswith((".hex", ".ihx", ".eep")):
        text = raw.decode("ascii", "replace")
        data, base = parse_ihex(text)
        print(f"intel hex: {len(data)} bytes, base 0x{base:08x}")
        if out:
            with open(out, "wb") as fh:
                fh.write(data)
            print(f"wrote {out}")
    else:
        data, base = raw, 0
        print(f"raw binary: {len(data)} bytes")

    esp = parse_esp_image(data) if (as_esp or data[:1] == bytes([ESP_MAGIC])) else None
    if esp:
        print("\n-- esp image header --")
        print(f"  segments   : {esp['segments']}")
        print(f"  spi mode   : {esp['spi_mode']}")
        print(f"  flash      : {esp['flash_size']} @ {esp['flash_freq']}")
        print(f"  entry point: 0x{esp['entry']:08x}")
        for i, s in enumerate(esp["seg_list"]):
            print(f"  seg {i}: load=0x{s['load']:08x} len={s['len']:>8} "
                  f"file_off=0x{s['file_off']:x}")
        print("\n  -> load each segment in ghidra at its load address")

    if as_avr:
        avr_summary(data)

    print("\n-- strings --")
    for s in strings_in(data):
        print("  " + s)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="mcu firmware parser")
    ap.add_argument("path")
    ap.add_argument("--esp", action="store_true")
    ap.add_argument("--avr", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    return report(args.path, args.esp, args.avr, args.out)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        hex_text = (
            ":10010000214601360121470136007EFE09D2190140\n"
            ":100110002146017E17C20001FF5F16002148011928\n"
            ":00000001FF\n"
        )
        data, base = parse_ihex(hex_text)
        assert base == 0x0100, hex(base)
        assert len(data) == 32, len(data)
        assert data[0] == 0x21 and data[1] == 0x46, data[:4].hex()

        try:
            parse_ihex(":10010000214601360121470136007EFE09D2190100\n")
            raise AssertionError("bad checksum was accepted")
        except ValueError:
            pass

        img = bytes([ESP_MAGIC, 2, 0x02, 0x20]) + struct.pack("<I", 0x400D0018)
        img += struct.pack("<II", 0x3FFB0000, 4) + b"\x01\x02\x03\x04"
        img += struct.pack("<II", 0x400D0018, 8) + b"flag{esp}"[:8]
        info = parse_esp_image(img)
        assert info is not None and info["segments"] == 2, info
        assert info["entry"] == 0x400D0018, hex(info["entry"])
        assert info["seg_list"][0]["load"] == 0x3FFB0000, info["seg_list"]
        assert info["spi_mode"] == "DIO", info["spi_mode"]

        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.hex")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(hex_text)
            report(p, False, False, os.path.join(d, "t.bin"))
            assert os.path.exists(os.path.join(d, "t.bin"))
        print("selftest ok")
    else:
        sys.exit(main())
```

### Ghidra setup per family

```bash
# AVR: language "AVR8:LE:16:default" (or avr8:LE:24:extended for >128 KB parts)
analyzeHeadless /tmp/proj mcu -import flash.bin \
  -processor 'AVR8:LE:16:atmega256' -loader BinaryLoader -loader-baseAddr 0x0

# STM32 (Cortex-M, thumb only, flash at 0x08000000)
analyzeHeadless /tmp/proj mcu -import flash.bin \
  -processor 'ARM:LE:32:Cortex' -loader BinaryLoader -loader-baseAddr 0x08000000
# then in the GUI: File > Parse SVD (with the SVDLoader extension) and pick STM32F103.svd
#  -> peripheral registers become named symbols

# ESP32 xtensa needs the ghidra-xtensa extension; esp32 risc-v variants use RISCV:LE:32
analyzeHeadless /tmp/proj mcu -import app.bin \
  -processor 'RISCV:LE:32:RV32IMC' -loader BinaryLoader -loader-baseAddr 0x42000000

# radare2 equivalents
r2 -a avr -b 8 -m 0 flash.bin
r2 -a arm -b 16 -e asm.cpu=cortex -m 0x08000000 flash.bin
r2 -a xtensa -b 32 -m 0x400d0018 app.bin
```

## Variants & pitfalls

- **Lock bits set** -> `avrdude` reads back `0xFF` or garbage and verification fails.
  Reading fuses still works. A chip erase clears the lock bits *and* the firmware.
- **AVR word vs byte addresses**: a `jmp 0x1234` targets *word* 0x1234 = byte 0x2468.
  Getting this wrong makes every cross-reference wrong.
- **STM32 RDP level 1** - SRAM is still readable while the core runs, and the flash may be
  reachable via a debugger-visible buffer; level 2 disables the port entirely.
- **ESP32 flash encryption** - `espefuse.py summary` tells you. If `FLASH_CRYPT_CNT` is
  set, the dump is ciphertext and the key is in eFuse (not readable).
- **PIC configuration words** live outside the normal program space (e.g. 0x2007 on
  PIC16); a dump that omits them hides the protection state.
- **Bootloader vs application**: many boards run a bootloader at the reset vector that
  jumps to the app. Both are in the dump; the interesting code is usually the app.
- **Peripheral-heavy code is unreadable without an SVD**. Loading one turns
  `*(uint32_t*)0x40021018 |= 4` into `RCC->APB2ENR |= GPIOA_EN`, which is the difference
  between guessing and reading.

## Tools

- `avrdude`, `avr-objdump`, `avr-gcc` toolchain; `srec_cat`/`srec_info` for HEX.
- `esptool.py`, `espefuse.py`, `gen_esp32part.py`, `mkspiffs`.
- `openocd`, `st-flash`, `st-info`, `stm32flash`, `nrfjprog`, `mspdebug`, `picotool`.
- `minipro` (TL866), `pk2cmd`/PICkit for PIC.
- `ghidra` (+ SVD-Loader, ghidra-xtensa), `radare2`/`rizin`, `binwalk`.
- CMSIS SVD files (published per vendor) for ARM peripheral naming.

## References

- Atmel/Microchip ATmega and ATtiny datasheets for fuse and lock-bit tables.
- Espressif esptool documentation, including the firmware image format.
- STMicroelectronics reference manuals for the flash option bytes and RDP levels.
- Ghidra documentation on the BinaryLoader and processor language selection.
