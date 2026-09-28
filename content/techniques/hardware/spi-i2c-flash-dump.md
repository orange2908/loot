---
title: "SPI and I2C Flash Dumping - flashrom, Bus Pirate, CH341A"
category: hardware
subcategory: flash
type: technique
tags: [spi, i2c, flashrom, bus-pirate, ch341a, soic8, chip-clip, eeprom, w25q, at24c, sop8, in-circuit, hot-air, i2ctools, sigrok, flash-dump]
difficulty: medium
summary: "Read a serial flash or EEPROM chip off a board - in circuit with a clip or desoldered - and verify the dump is real."
when_to_use:
  - "The board has an 8-pin SOIC chip next to the SoC"
  - "You need the firmware and there is no UART or JTAG access"
  - "You want to modify firmware and write it back"
tools: [flashrom, ch341a, bus-pirate, i2c-tools, binwalk, soic8-clip]
related: [firmware-extraction, uart-serial, jtag-swd, logic-analyzer-decoding]
---

## TL;DR

Most embedded firmware sits in an 8-pin SPI NOR flash (Winbond `W25Q`, Macronix `MX25`,
GigaDevice `GD25`) or a tiny I2C EEPROM (`AT24C`, `24LC`). Clip a SOIC-8 test clip on,
connect a CH341A or Bus Pirate, run `flashrom -p ch341a_spi -r dump.bin`, and take
**three dumps and compare** - an in-circuit read that differs between runs is unreliable.

## Recognise it

- An 8-pin (SOIC-8 / SOP-8 / WSON-8) chip near the SoC, marked e.g.
  `W25Q64FVSIG`, `MX25L12835F`, `GD25Q128C`, `25L8005`.
- A 6-pin SOT-23 or 8-pin chip marked `24C02`, `24LC256`, `AT24C64` -> I2C EEPROM
  (small, for config/MAC/calibration, not firmware).
- Larger TSOP-48 parts -> parallel NAND; needs a dedicated programmer.
- BGA -> you are not desoldering that in a CTF; use another route.

## Theory

### Part numbering

`W25Q64` -> Winbond, Q series (quad SPI), **64 Mbit = 8 MiB**.
`MX25L12835F` -> Macronix, 128 Mbit = 16 MiB.
`AT24C256` -> Atmel I2C EEPROM, 256 Kbit = 32 KiB.

The number after the family letters is the size in **megabits** for SPI NOR and
**kilobits** for I2C EEPROM. Divide by 8 for bytes.

### SOIC-8 SPI flash pinout (pin 1 = dot/notch, counter-clockwise)

```
      +--\/--+
  /CS |1    8| VCC (3.3V)
   DO |2    7| /HOLD (tie to VCC)
 /WP  |3    6| CLK
  GND |4    5| DI
      +------+
```

| Pin | Name | Connect to |
|---|---|---|
| 1 | /CS (chip select) | programmer CS |
| 2 | DO (MISO) | programmer MISO |
| 3 | /WP | VCC (3.3 V) |
| 4 | GND | GND |
| 5 | DI (MOSI) | programmer MOSI |
| 6 | CLK | programmer CLK |
| 7 | /HOLD | VCC |
| 8 | VCC | 3.3 V |

### SPI flash command set (JEDEC-ish, near universal)

| Opcode | Meaning |
|---|---|
| `0x9F` | RDID - read JEDEC id (manufacturer, type, capacity) |
| `0x90` / `0xAB` | read manufacturer/device id (legacy) |
| `0x03` | READ (single, up to ~50 MHz) |
| `0x0B` | FAST READ (with a dummy byte) |
| `0x05` | read status register 1 (bit0 = WIP/busy) |
| `0x01` | write status register |
| `0x06` | write enable |
| `0x02` | page program (256-byte pages) |
| `0x20` | sector erase (4 KiB) |
| `0xD8` | block erase (64 KiB) |
| `0xC7` / `0x60` | chip erase |
| `0x5A` | read SFDP parameter table |

`0x9F` returns 3 bytes: manufacturer (`0xEF` Winbond, `0xC2` Macronix, `0xC8` GigaDevice,
`0x20` Micron/ST, `0x1F` Atmel/Adesto, `0xBF` SST), memory type, and capacity as
`log2(bytes)` (e.g. `0x17` = 2^23 = 8 MiB).

### In-circuit vs desoldered

In-circuit reading works when the host SoC is held in reset (or unpowered) and the flash
is not being driven. Problems:

- The SoC back-powers through its I/O pins and fights the programmer.
- Other devices share the SPI bus.
- Decoupling capacitance loads the clock; you may need a slower clock.

Mitigations: hold the SoC in reset (pull nRST low), cut power to the rest of the board,
or desolder the chip (hot air, 300-350 C, or a chip-quik low-melt alloy).

## Attack

1. Read the chip marking; look up the part and its size.
2. Clip a SOIC-8 test clip on with pin 1 aligned to the dot.
3. Power the chip from the programmer at 3.3 V (or 1.8 V for a 1.8 V part -
   using 3.3 V on a 1.8 V flash destroys it).
4. `flashrom --probe` to confirm the chip is detected and the JEDEC id matches.
5. Read three times, compare hashes. If they differ, the read is unreliable.
6. `binwalk` the dump and extract as in `firmware-extraction`.
7. To modify: patch the image, `flashrom -w`, verify.

## Code

### flashrom

```bash
# what programmers this build supports
flashrom --list-supported | head -40

# probe: does it see a chip, and is the id right?
flashrom -p ch341a_spi
flashrom -p buspirate_spi:dev=/dev/ttyUSB0
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M
flashrom -p ft2232_spi:type=2232H,port=A,divisor=4
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000        # raspberry pi
flashrom -p serprog:dev=/dev/ttyACM0:115200                   # arduino frser
flashrom -p dediprog

# read (the important part). -c forces a chip model when autodetect is ambiguous
flashrom -p ch341a_spi -r dump1.bin
flashrom -p ch341a_spi -c W25Q64.V -r dump1.bin
flashrom -p ch341a_spi -r dump2.bin && flashrom -p ch341a_spi -r dump3.bin
sha256sum dump1.bin dump2.bin dump3.bin        # all three MUST match

# slower clock if reads are inconsistent
flashrom -p ch341a_spi -c W25Q64.V -r dump.bin --progress
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=30k -r dump.bin

# write and verify
flashrom -p ch341a_spi -c W25Q64.V -w patched.bin
flashrom -p ch341a_spi -c W25Q64.V -v patched.bin
flashrom -p ch341a_spi -c W25Q64.V -E                  # erase whole chip
flashrom -p ch341a_spi --layout layout.txt --image rootfs -w new.bin   # partial write

# layout file format (offset:end name), used with --image
cat > layout.txt <<'EOF'
00000000:0003ffff bootloader
00040000:0004ffff env
00050000:0017ffff kernel
00180000:007fffff rootfs
EOF
```

### Bus Pirate

```bash
# connect at 115200 8N1 and enter binary SPI mode via flashrom, or drive it by hand:
picocom -b 115200 /dev/ttyUSB0

# in the bus pirate terminal:
#   m        -> mode menu; choose 5 (SPI)
#            -> speed 1 (30 kHz to start), clock idle low, output type: normal (3.3V)
#   W        -> enable the on-board power supplies (capital W)
#   P        -> enable pull-ups if the board needs them
#   v        -> show pin voltages (sanity check)
#
#   read the JEDEC id: CS low, send 0x9F, read 3 bytes, CS high
#   [0x9F r:3]
#   -> e.g. READ: 0xEF 0x40 0x17   = Winbond, W25Q64, 2^23 = 8 MiB
#
#   read 16 bytes from address 0:
#   [0x03 0x00 0x00 0x00 r:16]
#
#   read the status register:
#   [0x05 r:1]

# then let flashrom do the bulk read
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r dump.bin
```

### CH341A notes

```bash
# the ubiquitous black/green usb programmer. two caveats:
#  1. most clones output 5 V on the data lines even in "3.3 V" mode -> can damage
#     1.8 V and some 3.3 V parts. The common fix is to cut the trace to the 5 V rail
#     of the level buffer and tie it to 3.3 V.
#  2. it needs the chip powered from the programmer; in-circuit it may not supply enough.
lsusb | grep 1a86                    # 1a86:5512 QinHeng CH341A
flashrom -p ch341a_spi --probe
flashrom -p ch341a_spi -c MX25L6405 -r dump.bin
# if flashrom cannot identify the chip, pass -c with the exact model from the marking
flashrom -L | grep -i w25q64
```

### I2C EEPROM

```bash
# on a linux host with an i2c adapter (raspberry pi, ft232h, bus pirate)
sudo modprobe i2c-dev
i2cdetect -l                              # list buses
i2cdetect -y 1                            # scan bus 1 for addresses (0x50-0x57 = eeprom)
i2cdump -y 1 0x50                         # dump 256 bytes
i2cdump -y 1 0x50 b                       # byte mode
i2cget -y 1 0x50 0x00                     # read one byte
i2cset -y 1 0x50 0x00 0x41                # write one byte (careful)

# larger eeproms (>2 Kbit) need a 16-bit address, which i2cdump cannot do directly
# use the eeprog tool, or the python snippet below
eeprog -f -x -r 0:0x8000 /dev/i2c-1 0x50 > eeprom.bin

# kernel driver route (raspberry pi)
echo 24c256 0x50 | sudo tee /sys/bus/i2c/devices/i2c-1/new_device
sudo cat /sys/bus/i2c/devices/1-0050/eeprom > eeprom.bin
```

### Python: SPI flash read over an FT232H / spidev, and dump sanity checks

```python
#!/usr/bin/env python3
"""spiflash.py - read a SPI NOR flash and sanity-check the dump.

Two backends:
  * spidev  (linux, e.g. raspberry pi /dev/spidev0.0)
  * pyftdi  (FT232H/FT2232H usb adapter)

Also works offline: `--check dump.bin` runs the validation heuristics on an
existing dump without any hardware.

Usage:
  python3 spiflash.py --backend spidev --size 0x800000 -o dump.bin
  python3 spiflash.py --check dump.bin
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from collections import Counter

JEDEC = {
    0xEF: "Winbond", 0xC2: "Macronix", 0xC8: "GigaDevice", 0x20: "Micron/ST",
    0x1F: "Atmel/Adesto", 0xBF: "SST", 0x01: "Spansion/Cypress", 0x9D: "ISSI",
    0x0B: "XTX", 0x68: "Boya", 0x5E: "Zbit",
}

CMD_RDID = 0x9F
CMD_READ = 0x03
CMD_RDSR = 0x05


def decode_rdid(b: bytes) -> str:
    if len(b) < 3:
        return "short response"
    manuf, mtype, cap = b[0], b[1], b[2]
    size = 1 << cap if 0x10 <= cap <= 0x1B else 0
    name = JEDEC.get(manuf, f"unknown(0x{manuf:02x})")
    human = f"{size // (1024 * 1024)} MiB" if size >= 1 << 20 else f"{size} bytes"
    return (f"manufacturer=0x{manuf:02x} ({name}) type=0x{mtype:02x} "
            f"capacity=0x{cap:02x} -> {human if size else 'unknown size'}")


def read_spidev(bus: int, dev: int, size: int, speed: int) -> bytes:
    import spidev  # type: ignore

    spi = spidev.SpiDev()
    spi.open(bus, dev)
    spi.max_speed_hz = speed
    spi.mode = 0
    rdid = spi.xfer2([CMD_RDID, 0, 0, 0])[1:]
    print("[rdid]", decode_rdid(bytes(rdid)))
    out = bytearray()
    chunk = 4096
    for addr in range(0, size, chunk):
        hdr = [CMD_READ, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF]
        res = spi.xfer2(hdr + [0] * chunk)
        out.extend(res[4:])
        if addr % 0x40000 == 0:
            print(f"  {addr:#010x} / {size:#x}", file=sys.stderr)
    spi.close()
    return bytes(out[:size])


def read_ftdi(url: str, size: int, freq: int) -> bytes:
    from pyftdi.spi import SpiController  # type: ignore

    ctrl = SpiController()
    ctrl.configure(url)
    slave = ctrl.get_port(cs=0, freq=freq, mode=0)
    print("[rdid]", decode_rdid(bytes(slave.exchange([CMD_RDID], 3))))
    out = bytearray()
    chunk = 4096
    for addr in range(0, size, chunk):
        hdr = [CMD_READ, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF]
        out.extend(slave.exchange(hdr, chunk))
        if addr % 0x40000 == 0:
            print(f"  {addr:#010x} / {size:#x}", file=sys.stderr)
    return bytes(out[:size])


def check(data: bytes) -> list[str]:
    """Heuristics that catch a bad in-circuit read."""
    notes: list[str] = []
    n = len(data)
    notes.append(f"size      : {n} bytes ({n / 1024 / 1024:.2f} MiB)")
    notes.append(f"sha256    : {hashlib.sha256(data).hexdigest()}")

    counts = Counter(data)
    top, topn = counts.most_common(1)[0]
    notes.append(f"most common byte: 0x{top:02x} ({topn / n:.1%})")
    if topn / n > 0.98:
        notes.append("!! almost entirely one byte - chip not responding or erased")
    if len(counts) < 8:
        notes.append("!! fewer than 8 distinct byte values - bad read")

    if n & (n - 1):
        notes.append("!! size is not a power of two - unusual for serial flash")

    # a real dump has ascii somewhere
    ascii_run = 0
    best = 0
    for b in data[: min(n, 1 << 20)]:
        if 0x20 <= b < 0x7F:
            ascii_run += 1
            best = max(best, ascii_run)
        else:
            ascii_run = 0
    notes.append(f"longest ascii run in first MiB: {best}")
    if best < 8:
        notes.append("!! no ascii strings - possibly encrypted, or a failed read")

    # repeated blocks mean address lines are not being driven
    block = 0x1000
    if n >= block * 4:
        blocks = {data[i:i + block] for i in range(0, min(n, block * 64), block)}
        if len(blocks) <= 2:
            notes.append("!! identical 4 KiB blocks - address lines stuck, bad clip")

    # known magics
    for magic, name in ((b"hsqs", "squashfs"), (b"\x27\x05\x19\x56", "uImage"),
                        (b"UBI#", "UBI"), (b"\x85\x19", "JFFS2"), (b"U-Boot", "U-Boot")):
        idx = data.find(magic)
        if idx >= 0:
            notes.append(f"found {name} at 0x{idx:08x}  <- dump looks real")
    return notes


def main() -> int:
    ap = argparse.ArgumentParser(description="spi flash reader and dump validator")
    ap.add_argument("--backend", choices=["spidev", "ftdi"], default="spidev")
    ap.add_argument("--bus", type=int, default=0)
    ap.add_argument("--dev", type=int, default=0)
    ap.add_argument("--url", default="ftdi://ftdi:232h/1")
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0x800000)
    ap.add_argument("--speed", type=lambda s: int(s, 0), default=1_000_000)
    ap.add_argument("-o", "--out", default="dump.bin")
    ap.add_argument("--check")
    args = ap.parse_args()

    if args.check:
        with open(args.check, "rb") as fh:
            for line in check(fh.read()):
                print(line)
        return 0

    if args.backend == "spidev":
        data = read_spidev(args.bus, args.dev, args.size, args.speed)
    else:
        data = read_ftdi(args.url, args.size, args.speed)
    with open(args.out, "wb") as fh:
        fh.write(data)
    print(f"wrote {len(data)} bytes to {args.out}")
    for line in check(data):
        print(line)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        assert "Winbond" in decode_rdid(bytes([0xEF, 0x40, 0x17]))
        assert "8 MiB" in decode_rdid(bytes([0xEF, 0x40, 0x17]))
        assert "Macronix" in decode_rdid(bytes([0xC2, 0x20, 0x18]))

        bad = b"\xff" * 0x10000
        notes = check(bad)
        assert any("almost entirely one byte" in n for n in notes), notes

        good = (b"\x00" * 0x1000 + b"U-Boot 2016.05 for ctfboard\x00" +
                bytes(range(256)) * 60 + b"hsqs" + b"\x11" * 0x2000)
        good += bytes(range(256)) * ((0x10000 - len(good)) // 256 + 1)
        notes = check(good[:0x10000])
        assert any("U-Boot" in n for n in notes), notes
        assert any("squashfs" in n for n in notes), notes
        print("\n".join(notes))
        print("selftest ok")
    else:
        sys.exit(main())
```

## Variants & pitfalls

- **Reads differ between runs** - the SoC is fighting the programmer. Hold nRST low,
  cut board power, drop the SPI clock, or desolder.
- **flashrom says "Multiple flash chip definitions match"** - pass `-c <model>` from
  `flashrom -L`.
- **flashrom says "No EEPROM/flash device found"** - check pin 1 orientation, clip
  contact (the #1 cause), and that VCC is actually reaching pin 8.
- **1.8 V parts** (`W25Q...IM` with a `W` suffix, many modern phones/routers) are
  destroyed by a 3.3 V programmer. Check the datasheet suffix.
- **Write protection** - `/WP` low plus a status-register block bit prevents writing.
  Tie `/WP` to VCC and clear the block-protect bits (`flashrom` usually handles it;
  `--wp-disable` on builds that have it).
- **4-byte addressing** on chips >16 MiB (128 Mbit+): the `0x03` 3-byte address command
  only reaches 16 MiB. flashrom handles it; hand-rolled code must use `0x13`/`0xEB`
  or the extended-address register.
- **NAND is not this.** TSOP-48 parallel NAND needs a proper programmer and ECC/OOB
  handling; dumps have spare bytes interleaved.

## Tools

- `flashrom` - the universal SPI reader/writer.
- CH341A USB programmer (cheap, needs the 3.3 V mod), Bus Pirate, FT2232H boards,
  Raspberry Pi `spidev`, Dediprog SF100 (professional).
- SOIC-8 test clip (Pomona 5250 or a clone) and a SOIC-8 to DIP adapter for desoldered parts.
- `i2c-tools` (`i2cdetect`, `i2cdump`, `i2cget`), `eeprog` for I2C.
- `binwalk` afterwards; `sigrok`/PulseView to debug a failing bus.

## References

- flashrom documentation: supported programmers, chips and the layout file format.
- JEDEC JEP106 manufacturer identification code assignments.
- Winbond W25Q series datasheet for the standard SPI NOR command set.
