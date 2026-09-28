---
title: "JTAG and SWD - Pinout Discovery, OpenOCD, Halting and Dumping Flash"
category: hardware
subcategory: jtag
type: technique
tags: [jtag, swd, openocd, jtagulator, tck, tms, tdi, tdo, swdio, swclk, idcode, tap, boundary-scan, gdb, stm32, nrf52, readout-protection, flash-dump]
difficulty: hard
summary: "Find the debug port on an unlabelled board, connect OpenOCD, halt the CPU and read flash and RAM out of a running target."
when_to_use:
  - "You see a 4-10 pin header or test points that are not UART"
  - "You need memory contents that UART cannot give you"
  - "The firmware is only in internal flash and there is no SPI chip to clip"
tools: [openocd, jtagulator, jtagenum, gdb-multiarch, st-link, jlink, blackmagic]
related: [uart-serial, spi-i2c-flash-dump, mcu-reversing, fault-injection-glitching]
---

## TL;DR

JTAG is 4 wires (TCK, TMS, TDI, TDO, plus optional TRST) and SWD is 2 (SWCLK, SWDIO).
Find them with a JTAGulator or `JTAGenum` on an Arduino, confirm with an IDCODE read,
then `openocd -f interface/<adapter>.cfg -f target/<chip>.cfg`, `telnet localhost 4444`,
`halt`, `dump_image fw.bin 0x08000000 0x20000`. If the read fails, the chip has
readout protection.

## Recognise it

- A 2x5 (10-pin, 1.27 mm), 2x10 (20-pin, 2.54 mm), or 4-6 pin inline header labelled
  `JTAG`, `SWD`, `DEBUG`, `J-LINK`, or nothing.
- Silkscreen `TCK TMS TDI TDO`, or `SWDIO SWCLK RST`.
- Test points near the MCU in a tight cluster of 4-6.
- The datasheet for the identified MCU names the debug pins by package pin number.

## Theory

### Standard pinouts

**ARM 10-pin Cortex Debug (1.27 mm):**

```
  1 VTref     2 SWDIO/TMS
  3 GND       4 SWCLK/TCK
  5 GND       6 SWO/TDO
  7 KEY       8 NC/TDI
  9 GNDDetect 10 nRESET
```

**ARM 20-pin JTAG (2.54 mm):** VTref=1, TRST=3, TDI=5, TMS/SWDIO=7, TCK/SWCLK=9,
TDO/SWO=13, nSRST=15; GND on 4,6,8,10,12,14,16,18,20.

### The JTAG TAP state machine

TMS drives a 16-state FSM clocked by TCK. What matters in practice:

- Holding TMS high for 5 TCK cycles always returns to Test-Logic-Reset.
- From Test-Logic-Reset, the instruction register loads IDCODE by default, so simply
  clocking TDO out after a reset gives you a 32-bit IDCODE per TAP in the chain.
- IDCODE format: bit0 = 1, bits 1-11 = JEDEC manufacturer, bits 12-27 = part number,
  bits 28-31 = version. Manufacturer `0x020` = STMicro, `0x00E`/`0x23B` = ARM,
  `0x015` = NXP/Philips, `0x049` = Xilinx.

That is why IDCODE scanning works: you do not need to know the chip first.

### SWD

Two wires, ARM-specific. A host writes an 8-bit request (start, APnDP, RnW, A[2:3],
parity, stop, park), the target replies with a 3-bit ACK then 32 bits + parity.
Reading the IDCODE (DP register 0x00) is the handshake. SWD and JTAG often share pins:
SWDIO=TMS, SWCLK=TCK, and a magic 16-bit sequence (`0xE79E`) switches JTAG to SWD.

### Protection

| Chip family | Protection | Effect |
|---|---|---|
| STM32 | RDP level 1 | debug works, flash reads return 0 / error; mass-erase on level change |
| STM32 | RDP level 2 | debug port permanently disabled |
| nRF51/52 | APPROTECT | AHB-AP locked; `recover` mass-erases |
| ESP32 | eFuse `JTAG_DISABLE` | no debug at all |
| Atmel SAM | GPNVM security bit | erase required |
| TI MSP430 | JTAG password/fuse | blown fuse = no JTAG |

A locked chip usually still allows **mass erase**, which destroys the firmware you want.
Recovering firmware from an RDP-1 STM32 is a known fault-injection target - see
`fault-injection-glitching`.

## Attack

1. Identify the MCU by its package markings; look up its debug pins.
2. If unlabelled, brute the pinout: JTAGulator (`j` for JTAG scan, `s` for SWD/UART),
   or `JTAGenum` flashed onto an Arduino/ESP32.
3. Confirm with an IDCODE read; decode the manufacturer to sanity check.
4. Start OpenOCD with the matching interface and target config.
5. `halt`, then read a little memory to confirm the connection is real.
6. `dump_image` the whole flash and the whole RAM.
7. If reads fail, check protection registers; consider glitching or another entry point.

## Code

### Discovering the pinout

```bash
# JTAGulator: a dedicated board that brute-forces channel assignments
# connect its channels to the candidate pads, set the target voltage, then:
#   V   -> set target system voltage (e.g. 3.3)
#   J   -> JTAG menu
#     I -> IDCODE scan (fastest, needs only TCK/TMS/TDO)
#     B -> BYPASS scan (identifies TDI too, and chain length)
#     R -> RTCK / adaptive clocking detect
#   U   -> UART menu (scan for TX/RX and baud)
#   S   -> SWD menu (IDCODE scan over 2 wires)
# it prints e.g. "TDI: 3  TDO: 0  TCK: 2  TMS: 1  IDCODE: 0x4BA00477"

# JTAGenum: same idea on an arduino/esp32 (no special hardware)
#   flash JTAGenum, open the serial console at 115200, then:
#     h  -> help
#     s  -> scan for a jtag tap (brute forces pin permutations)
#     i  -> idcode scan
#     b  -> boundary scan
#     x  -> irlen scan

# openocd itself can hunt for an SWD device once you guessed 2 of the pins
openocd -f interface/stlink.cfg -c "transport select hla_swd" -f target/stm32f1x.cfg \
        -c "init; dap info; exit"
```

### OpenOCD basics

```bash
# 1. list what configs exist for your adapter and target
ls /usr/share/openocd/scripts/interface/    # stlink.cfg, jlink.cfg, ftdi/*.cfg, cmsis-dap.cfg
ls /usr/share/openocd/scripts/target/       # stm32f1x.cfg, nrf52.cfg, at91sam*.cfg, esp32.cfg

# 2. connect (st-link + stm32f1)
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg

# ftdi-based adapter (ft2232h) with explicit pin mapping
openocd -f interface/ftdi/ft2232h-module-swd.cfg -f target/stm32f4x.cfg

# raspberry pi bitbang (no adapter at all)
openocd -f interface/raspberrypi2-native.cfg -f target/stm32f1x.cfg

# generic: just read the IDCODE of an unknown jtag chain
openocd -f interface/jlink.cfg \
  -c "transport select jtag" \
  -c "adapter speed 100" \
  -c "jtag newtap unknown cpu -irlen 4 -expected-id 0x00000000" \
  -c "init; scan_chain; exit"

# 3. once openocd is up, drive it
telnet localhost 4444
# or one-shot commands from the shell:
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; dump_image fw.bin 0x08000000 0x10000; exit"
```

### The OpenOCD command set that matters

```text
# --- state ---
init
reset init            # reset and halt at the reset vector
reset halt
halt                  # stop the cpu wherever it is
resume
step
poll                  # is the target halted? what is the pc?
targets               # list targets and their state

# --- memory ---
mdw 0x08000000 16     # memory display, 16 words
mdh 0x20000000 8      # halfwords
mdb 0x20000000 32     # bytes
mww 0x20000000 0xdeadbeef
dump_image fw.bin 0x08000000 0x20000       # flash -> file (the money command)
dump_image ram.bin 0x20000000 0x5000       # sram
load_image patched.bin 0x08000000
verify_image fw.bin 0x08000000

# --- registers ---
reg                   # all core registers
reg pc
reg pc 0x08001234
arm semihosting enable

# --- flash ---
flash banks
flash info 0
flash probe 0
flash read_bank 0 fw.bin 0 0x20000          # read a whole bank
flash write_image erase unlock new.bin 0x08000000
flash erase_sector 0 0 last
stm32f1x unlock 0                            # clears RDP (MASS ERASES the chip)
stm32f1x options_read 0
nrf5 mass_erase                              # clears APPROTECT on nordic
at91sam3 gpnvm clear 0

# --- gdb ---
# openocd also listens on :3333 for gdb
```

Interactive gdb against OpenOCD's port 3333:

```text
$ gdb-multiarch
(gdb) target extended-remote localhost:3333
(gdb) set architecture arm
(gdb) monitor reset halt
(gdb) x/32wx 0x08000000
(gdb) dump binary memory fw.bin 0x08000000 0x08020000
(gdb) info registers
(gdb) break *0x08001234
(gdb) continue
```

```bash
# the same dump as a one-liner
gdb-multiarch -batch \
  -ex 'target extended-remote localhost:3333' \
  -ex 'monitor reset halt' \
  -ex 'dump binary memory fw.bin 0x08000000 0x08020000'
```

### Decoding an IDCODE

```python
#!/usr/bin/env python3
"""idcode.py - decode a JTAG IDCODE into manufacturer, part number and version.

IDCODE layout (32 bits, LSB first on the wire):
  bit  0      : always 1
  bits 1-11   : JEDEC manufacturer id (11 bits, with a continuation-code convention)
  bits 12-27  : part number
  bits 28-31  : version

Usage: python3 idcode.py 0x4BA00477 0x1BA01477
"""
from __future__ import annotations

import sys

# JEDEC bank-1 manufacturer ids as they appear in the 11-bit JTAG field
VENDORS = {
    0x03B: "Texas Instruments",
    0x00E: "Freescale/NXP",
    0x015: "NXP (Philips)",
    0x01F: "Atmel",
    0x020: "STMicroelectronics",
    0x023: "Intel",
    0x049: "Xilinx",
    0x04B: "ARM Ltd",
    0x07F: "Lattice",
    0x093: "Infineon",
    0x097: "Cypress/Infineon",
    0x0E5: "Marvell",
    0x11D: "Microchip",
    0x15D: "Espressif",
    0x1BA: "ARM (SWD DPIDR family)",
    0x23B: "ARM Cortex-M DAP",
}

KNOWN = {
    0x4BA00477: "ARM Cortex-M3/M4 DAP (JTAG-DP)",
    0x2BA01477: "ARM Cortex-M3/M4 DAP (SW-DP)",
    0x1BA01477: "ARM Cortex-M0/M0+ DAP (SW-DP)",
    0x6BA02477: "ARM Cortex-M7 DAP",
    0x0BB11477: "ARM Cortex-M0 DAP",
    0x3BA00477: "ARM Cortex-A DAP",
    0x06414041: "STM32F1 medium density",
    0x06413041: "STM32F4",
    0x0BC11477: "nRF51 (Nordic)",
    0x2BA01477: "nRF52 (Nordic, SWD)",
}


def decode(idcode: int) -> dict:
    if idcode in (0x00000000, 0xFFFFFFFF):
        return {"valid": False, "why": "all zeros/ones - no TAP or wrong pins"}
    if not idcode & 1:
        return {"valid": False, "why": "LSB is 0 - not a valid IDCODE (check bit order)"}
    manuf = (idcode >> 1) & 0x7FF
    part = (idcode >> 12) & 0xFFFF
    version = (idcode >> 28) & 0xF
    return {
        "valid": True,
        "idcode": idcode,
        "manufacturer_id": manuf,
        "manufacturer": VENDORS.get(manuf, f"unknown (0x{manuf:03x})"),
        "part": part,
        "version": version,
        "known": KNOWN.get(idcode, ""),
    }


def report(idcode: int) -> None:
    d = decode(idcode)
    print(f"\nIDCODE 0x{idcode:08X}")
    if not d["valid"]:
        print(f"  INVALID: {d['why']}")
        return
    print(f"  manufacturer : 0x{d['manufacturer_id']:03X}  {d['manufacturer']}")
    print(f"  part number  : 0x{d['part']:04X}")
    print(f"  version      : {d['version']}")
    if d["known"]:
        print(f"  match        : {d['known']}")
    if d["manufacturer_id"] in (0x04B, 0x23B, 0x1BA):
        print("  -> ARM debug access port: use SWD or JTAG with openocd target/*.cfg")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    for a in argv[1:]:
        report(int(a, 0))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        d = decode(0x4BA00477)
        assert d["valid"], d
        assert d["manufacturer_id"] == 0x23B, hex(d["manufacturer_id"])
        assert d["part"] == 0xBA00, hex(d["part"])
        assert decode(0x00000000)["valid"] is False
        assert decode(0xFFFFFFFF)["valid"] is False
        assert decode(0x12345678)["valid"] is False     # LSB 0
        for v in (0x4BA00477, 0x06414041, 0x0BC11477):
            report(v)
        print("\nselftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Full dump workflow

```bash
#!/bin/sh
# jtag-dump.sh - halt a target and dump flash + ram with openocd
set -eu
IFACE="${1:-interface/stlink.cfg}"
TARGET="${2:-target/stm32f1x.cfg}"
FLASH_BASE="${3:-0x08000000}"
FLASH_SIZE="${4:-0x20000}"

openocd -f "$IFACE" -f "$TARGET" -c "
  init
  reset halt
  echo \"--- registers ---\"
  reg
  echo \"--- flash banks ---\"
  flash banks
  flash probe 0
  echo \"--- dumping flash ---\"
  dump_image flash.bin $FLASH_BASE $FLASH_SIZE
  echo \"--- dumping sram ---\"
  dump_image sram.bin 0x20000000 0x5000
  echo \"--- option bytes (stm32) ---\"
  mdw 0x1FFFF800 4
  shutdown
"

ls -l flash.bin sram.bin
# a chip with readout protection returns all 0x00 or all 0xFF
python3 -c "
import sys
d=open('flash.bin','rb').read()
print('unique bytes:', len(set(d)))
print('all zero:', d.count(0)==len(d))
print('all ff:', d.count(255)==len(d))
"
strings -n 6 flash.bin | head -20
binwalk flash.bin
```

## Variants & pitfalls

- **IDCODE reads as 0x00000000 or 0xFFFFFFFF** - wrong pins, no power, held in reset,
  or the debug port is disabled by fuse.
- **`Error: init mode failed (unable to connect to the target)`** - try
  `reset_config srst_only srst_nogate`, lower `adapter speed` to 100 kHz, or hold the
  reset line and connect under reset (`-c "reset_config connect_assert_srst"`).
- **The bootloader disables the debug port early** - connect under reset so you halt at
  the reset vector before that code runs.
- **Dump is all `0x00`** - readout protection. Do **not** run `unlock` unless you accept a
  mass erase; a protected chip may still leak via SRAM residue, a bootloader command
  interface, or glitching.
- **Multiple TAPs in the chain** - you must declare every TAP with the right IRLEN or the
  chain scan is garbage. `scan_chain` after a blind `jtag newtap` helps.
- **SWD vs JTAG on shared pins** - if JTAG fails, try `transport select swd`; many modern
  parts only expose SWD.
- **nRF52 `recover`** erases the chip. Try reading first; APPROTECT on older silicon has
  documented weaknesses but that is a fault-injection topic.

## Tools

- `openocd` - the universal driver; check `scripts/interface` and `scripts/target`.
- `JTAGulator` - hardware pinout brute-forcer, also does UART and SWD.
- `JTAGenum` - the same idea on an Arduino/ESP32.
- `gdb-multiarch` - interactive debugging over OpenOCD's port 3333.
- Adapters: ST-Link V2 (cheap, SWD), J-Link, FT2232H boards, CMSIS-DAP,
  Black Magic Probe (built-in gdb server), Raspberry Pi bitbang.
- `pyOCD` - Python alternative to OpenOCD for CMSIS-DAP targets.

## References

- OpenOCD user guide: transports, target configuration and the command reference.
- ARM Debug Interface architecture specification (SWD packet format, DPIDR).
- IEEE 1149.1 for the TAP state machine and IDCODE layout.
