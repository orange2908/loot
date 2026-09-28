---
title: "UART Baud Scanner - Auto-Detect the Right Rate by Scoring Printability"
category: hardware
subcategory: uart
type: script
tags: [uart, serial, baud-rate, pyserial, autobaud, printability, scoring, ftdi, ch340, bootloader, console, detection, scanner]
summary: "Complete pyserial tool that sweeps baud rates and framings, scores the output for readable text, and reports the best match."
tools: [pyserial, python, picocom]
related: [uart-serial, protocol-decoders, hardware-tools-cheatsheet, logic-analyzer-decoding]
---

## What it does

Opens a serial port at each candidate baud rate (and optionally each framing), reads for a
fixed window, and scores the bytes on how much they look like a console log: printable
ratio, line structure, English-ish word shape and the presence of known boot-log tokens.
Prints a ranked table and the best sample.

It also has an **offline mode** so you can score bytes you already captured, and a
**bit-timing mode** that computes the baud rate from the shortest pulse in a logic capture.

## Usage

```bash
# install the dependency
pip install pyserial

# sweep the standard rates for 2 seconds each (power-cycle the board during the sweep)
python3 uart_baud_scanner.py /dev/ttyUSB0

# be thorough: every rate, every common framing, 3 seconds each
python3 uart_baud_scanner.py /dev/ttyUSB0 --all-framings --seconds 3

# just a few rates, and send a newline to provoke a prompt
python3 uart_baud_scanner.py /dev/ttyUSB0 --bauds 115200 57600 9600 --poke

# score a file you already captured
python3 uart_baud_scanner.py --offline dump.bin

# compute the baud from a measured shortest pulse (in samples) and sample rate
python3 uart_baud_scanner.py --from-pulse 87 --samplerate 1000000

# list the serial ports the system can see
python3 uart_baud_scanner.py --list
```

## Script

```python
#!/usr/bin/env python3
"""uart_baud_scanner.py - find the baud rate of an unknown UART by scoring its output.

Modes:
  1. live sweep   : open a serial port at each candidate rate and score what arrives
  2. offline      : score an already-captured byte stream
  3. from-pulse   : derive the baud rate from the shortest pulse in a logic capture
  4. list         : enumerate serial ports

Scoring combines:
  * printable-byte ratio (the dominant term)
  * line structure (newlines at plausible intervals)
  * run-length sanity (long runs of one byte are a wrong-baud artefact)
  * known boot-log tokens (U-Boot, Linux, BusyBox, login:, ...)

Only pyserial is required, and only for the live sweep.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass

# Ordered by how likely you are to meet them on embedded hardware.
STANDARD_BAUDS = [
    115200, 57600, 38400, 19200, 9600, 230400, 460800, 921600,
    1500000, 74880, 250000, 500000, 128000, 4800, 2400, 1800, 1200, 600, 300,
]

FRAMINGS = [
    # (data bits, parity, stop bits) - 8N1 first because it is nearly universal
    (8, "N", 1),
    (8, "E", 1),
    (8, "O", 1),
    (7, "E", 1),
    (7, "O", 1),
    (8, "N", 2),
    (7, "N", 1),
]

PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

TOKENS = [
    b"U-Boot", b"Linux", b"BusyBox", b"login:", b"Password", b"root@", b"#",
    b"Hit any key", b"autoboot", b"bootargs", b"Starting kernel", b"init",
    b"console", b"ttyS0", b"ttyAMA0", b"CPU:", b"DRAM:", b"Flash:", b"MAC:",
    b"eth0", b"Kernel", b"rootfs", b"squashfs", b"jffs2", b"Welcome",
    b"ERROR", b"WARN", b"version", b"Booting", b"RedBoot", b"CFE", b"Uncompressing",
]

WORD_RE = re.compile(rb"[A-Za-z]{3,}")


@dataclass
class Result:
    baud: int
    framing: tuple[int, str, int]
    data: bytes
    score: float
    detail: dict

    @property
    def framing_str(self) -> str:
        return f"{self.framing[0]}{self.framing[1]}{self.framing[2]}"

    def preview(self, n: int = 72) -> str:
        text = self.data[:n].decode("utf-8", "replace")
        return text.replace("\n", "\\n").replace("\r", "\\r")


def score_bytes(data: bytes) -> tuple[float, dict]:
    """Return (score in 0..1, breakdown). Higher is more likely to be real text."""
    detail: dict = {}
    n = len(data)
    if n == 0:
        return 0.0, {"reason": "no data"}

    printable = sum(1 for b in data if b in PRINTABLE)
    p_ratio = printable / n
    detail["printable"] = p_ratio

    # newlines: console output has line structure; aim for one per 20-120 bytes
    newlines = data.count(b"\n")
    if newlines:
        avg_line = n / newlines
        line_score = 1.0 if 8 <= avg_line <= 200 else 0.35
    else:
        line_score = 0.0 if n > 200 else 0.3
    detail["lines"] = line_score
    detail["newlines"] = newlines

    # long identical runs indicate a framing/baud mismatch
    longest = 1
    run = 1
    for i in range(1, n):
        if data[i] == data[i - 1]:
            run += 1
            longest = max(longest, run)
        else:
            run = 1
    run_penalty = 0.0 if longest <= 8 else min(0.5, (longest - 8) / 64.0)
    detail["longest_run"] = longest

    # alphabetic words are the strongest positive signal after printability
    words = WORD_RE.findall(data)
    word_chars = sum(len(w) for w in words)
    word_score = min(1.0, word_chars / max(1, n) * 2.0)
    detail["words"] = len(words)

    # known boot-log tokens: a big bonus, because they are unambiguous
    hits = [t.decode() for t in TOKENS if t in data]
    token_bonus = min(0.30, 0.10 * len(hits))
    detail["tokens"] = hits

    score = (0.50 * p_ratio + 0.15 * line_score + 0.20 * word_score
             + token_bonus - run_penalty)
    return max(0.0, min(1.0, score)), detail


def baud_from_pulse(shortest_samples: int, samplerate: int) -> tuple[int, int]:
    """Given the shortest pulse (in samples) and the sample rate, return
    (raw baud estimate, nearest standard rate)."""
    if shortest_samples <= 0:
        raise ValueError("shortest_samples must be positive")
    raw = samplerate / shortest_samples
    nearest = min(STANDARD_BAUDS, key=lambda b: abs(b - raw))
    return int(round(raw)), nearest


def list_ports() -> int:
    try:
        from serial.tools import list_ports  # type: ignore
    except ImportError:
        print("pyserial not installed: pip install pyserial", file=sys.stderr)
        return 1
    found = list(list_ports.comports())
    if not found:
        print("no serial ports found")
        return 1
    for p in found:
        print(f"{p.device:<24} {p.description}")
        if p.vid is not None:
            print(f"{'':24} vid:pid={p.vid:04x}:{p.pid:04x} serial={p.serial_number}")
    return 0


def sweep(port: str, bauds: list[int], framings: list[tuple[int, str, int]],
          seconds: float, poke: bool, read_bytes: int) -> list[Result]:
    import serial  # type: ignore

    parity_map = {
        "N": serial.PARITY_NONE,
        "E": serial.PARITY_EVEN,
        "O": serial.PARITY_ODD,
    }
    stop_map = {1: serial.STOPBITS_ONE, 2: serial.STOPBITS_TWO}
    bits_map = {7: serial.SEVENBITS, 8: serial.EIGHTBITS}

    results: list[Result] = []
    for baud in bauds:
        for framing in framings:
            bits, parity, stop = framing
            try:
                ser = serial.Serial(
                    port=port,
                    baudrate=baud,
                    bytesize=bits_map[bits],
                    parity=parity_map[parity],
                    stopbits=stop_map[stop],
                    timeout=0.2,
                    rtscts=False,
                    dsrdtr=False,
                    xonxoff=False,
                )
            except Exception as exc:                 # noqa: BLE001 - serial raises broadly
                print(f"  {baud:>8} {bits}{parity}{stop}: open failed ({exc})",
                      file=sys.stderr)
                continue

            with ser:
                ser.reset_input_buffer()
                ser.reset_output_buffer()
                if poke:
                    try:
                        ser.write(b"\r\n")
                        ser.flush()
                    except Exception:                # noqa: BLE001
                        pass
                buf = bytearray()
                end = time.time() + seconds
                while time.time() < end and len(buf) < read_bytes:
                    chunk = ser.read(512)
                    if chunk:
                        buf.extend(chunk)

            score, detail = score_bytes(bytes(buf))
            results.append(Result(baud, framing, bytes(buf), score, detail))
            tok = ",".join(detail.get("tokens", [])[:3])
            print(f"  {baud:>8} {bits}{parity}{stop}: score={score:.3f} "
                  f"bytes={len(buf):<6} printable={detail.get('printable', 0):.2f} "
                  f"{('tokens=' + tok) if tok else ''}")

    results.sort(key=lambda r: -r.score)
    return results


def print_results(results: list[Result], top: int = 5) -> None:
    if not results:
        print("\nno data captured at any rate - check TX/RX wiring and common ground")
        return
    print("\n=== ranked ===")
    print(f"{'baud':>9} {'fmt':>5} {'score':>7} {'bytes':>7}  preview")
    for r in results[:top]:
        print(f"{r.baud:>9} {r.framing_str:>5} {r.score:>7.3f} "
              f"{len(r.data):>7}  {r.preview()}")

    best = results[0]
    if best.score < 0.35:
        print("\nno convincing match. things to try:")
        print("  * swap TX and RX")
        print("  * confirm a common ground")
        print("  * power-cycle the board DURING the sweep (boot logs are the loudest)")
        print("  * check the logic level (1.8 V boards need a 1.8 V adapter)")
        print("  * the line may be inverted (some vendors use inverted TTL)")
        return

    print(f"\nbest: {best.baud} baud {best.framing_str} (score {best.score:.3f})")
    if best.detail.get("tokens"):
        print("tokens seen: " + ", ".join(best.detail["tokens"]))
    print("\n--- captured output ---")
    print(best.data.decode("utf-8", "replace")[:2000])
    print("\n--- connect with ---")
    bits, parity, stop = best.framing
    print(f"  picocom -b {best.baud} /dev/... ")
    print(f"  screen /dev/... {best.baud}")
    print(f"  python3 -m serial.tools.miniterm /dev/... {best.baud}")
    if best.framing != (8, "N", 1):
        print(f"  (non-standard framing {bits}{parity}{stop}: "
              f"minicom -s, or pyserial with bytesize/parity/stopbits set)")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="detect a UART's baud rate by scoring output printability")
    ap.add_argument("port", nargs="?", help="serial device, e.g. /dev/ttyUSB0")
    ap.add_argument("--bauds", type=int, nargs="*", default=None,
                    help="candidate rates (default: the standard list)")
    ap.add_argument("--seconds", type=float, default=2.0,
                    help="listen window per candidate")
    ap.add_argument("--read-bytes", type=int, default=8192,
                    help="stop early once this many bytes arrive")
    ap.add_argument("--all-framings", action="store_true",
                    help="also try 8E1/8O1/7E1/7O1/8N2/7N1")
    ap.add_argument("--poke", action="store_true",
                    help="send CRLF before listening, to provoke a prompt")
    ap.add_argument("--offline", help="score an already-captured file instead")
    ap.add_argument("--from-pulse", type=int, default=None,
                    help="shortest pulse length in samples (with --samplerate)")
    ap.add_argument("--samplerate", type=int, default=1_000_000)
    ap.add_argument("--list", action="store_true", help="list serial ports and exit")
    args = ap.parse_args()

    if args.list:
        return list_ports()

    if args.from_pulse is not None:
        raw, nearest = baud_from_pulse(args.from_pulse, args.samplerate)
        err = abs(raw - nearest) / nearest * 100
        print(f"shortest pulse {args.from_pulse} samples at {args.samplerate} sps")
        print(f"raw estimate   : {raw} baud")
        print(f"nearest standard: {nearest} baud ({err:.1f}% away)")
        if err > 5:
            print("  warning: >5% from a standard rate - re-measure the pulse")
        return 0

    if args.offline:
        with open(args.offline, "rb") as fh:
            data = fh.read()
        score, detail = score_bytes(data)
        print(f"{args.offline}: {len(data)} bytes, score {score:.3f}")
        for k, v in detail.items():
            print(f"  {k}: {v}")
        print("\n--- preview ---")
        print(data[:1000].decode("utf-8", "replace"))
        return 0

    if not args.port:
        ap.print_help()
        return 2

    bauds = args.bauds or STANDARD_BAUDS
    framings = FRAMINGS if args.all_framings else [(8, "N", 1)]
    total = len(bauds) * len(framings)
    print(f"sweeping {args.port}: {total} combinations x {args.seconds}s "
          f"= about {total * args.seconds:.0f}s")
    print("power-cycle the board during the sweep for the loudest output\n")

    try:
        results = sweep(args.port, bauds, framings, args.seconds,
                        args.poke, args.read_bytes)
    except ImportError:
        print("pyserial not installed: pip install pyserial", file=sys.stderr)
        return 1
    print_results(results)
    return 0


def _selftest() -> None:
    boot = (b"\r\nU-Boot 2016.05 (Jan 01 2020 - 12:00:00)\r\n"
            b"DRAM:  128 MiB\r\nFlash: 16 MiB\r\n"
            b"Hit any key to stop autoboot:  3\r\n"
            b"Starting kernel ...\r\n"
            b"Linux version 3.10.14 (gcc version 4.8.5)\r\n"
            b"BusyBox v1.24.1 built-in shell (ash)\r\n"
            b"login: ")
    good, gdetail = score_bytes(boot)

    junk = bytes([0xF8, 0x9C, 0xE0, 0x03, 0xFC, 0x81] * 40)
    bad, _ = score_bytes(junk)

    stuck = b"\xff" * 240
    stuck_score, _ = score_bytes(stuck)

    assert good > 0.75, (good, gdetail)
    assert bad < 0.35, bad
    assert stuck_score < 0.35, stuck_score
    assert score_bytes(b"")[0] == 0.0
    assert "U-Boot" in gdetail["tokens"] and "Linux" in gdetail["tokens"], gdetail

    raw, nearest = baud_from_pulse(87, 10_000_000)
    assert nearest == 115200, (raw, nearest)
    raw2, nearest2 = baud_from_pulse(104, 1_000_000)
    assert nearest2 == 9600, (raw2, nearest2)

    r = Result(115200, (8, "N", 1), boot, good, gdetail)
    assert r.framing_str == "8N1"
    assert "U-Boot" in r.preview(200)
    print_results([r, Result(9600, (8, "N", 1), junk, bad, {})])
    print("\nselftest ok")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _selftest()
    else:
        sys.exit(main())
```

## Notes

- **Power-cycle during the sweep.** Most embedded UARTs are silent once booted; the boot
  log is what you are scoring.
- The `--poke` flag sends `\r\n`, which wakes a shell or bootloader prompt. It is safe on
  a Linux console and on U-Boot after autoboot, but it also *interrupts* autoboot - which
  is usually what you want anyway.
- If every rate scores low but you see *some* bytes, the levels are probably wrong
  (1.8 V board vs 3.3 V adapter) or the line is inverted.
- `--from-pulse` is for the logic-analyser path: measure the narrowest pulse in
  PulseView with cursors, pass the sample count and the capture rate, and you get the
  rate directly instead of guessing.
- 74880 baud is the ESP8266 ROM boot message rate; it is in the list for that reason.
- Non-8N1 framings are rare but do appear on industrial equipment; `--all-framings`
  multiplies the sweep time by seven, so only use it after 8N1 fails.
