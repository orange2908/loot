---
title: "Logic Analyzer Captures - Decoding SPI, I2C, UART and 1-Wire from a .sr File"
category: hardware
subcategory: logic-analysis
type: technique
tags: [sigrok, sigrok-cli, pulseview, logic-analyzer, srzip, spi, i2c, uart, one-wire, saleae, fx2lafw, decoder, protocol-decoder, csv, waveform, vcd]
difficulty: medium
summary: "Open a sigrok .sr or Saleae capture, work out which channel is which signal, and decode the bus traffic back into bytes."
when_to_use:
  - "The challenge hands you a .sr, .logicdata, .vcd or a CSV of samples"
  - "You captured a bus on real hardware and need the payload"
  - "You do not know which channel is CLK and which is DATA"
tools: [sigrok-cli, pulseview, python, binwalk]
related: [uart-serial, spi-i2c-flash-dump, protocol-decoders, rf-sdr-analysis]
---

## TL;DR

A `.sr` file is a ZIP: `metadata` tells you the sample rate and channel names,
`logic-1-1` is the packed sample data. `sigrok-cli -i cap.sr --show` prints the
metadata, and `-P <decoder>:<pin>=<channel>` runs a protocol decoder. If channel
roles are unknown, identify the **clock** (the most regular, highest-frequency channel)
and the **chip select** (idles high, goes low for bursts), and the rest follows.

## Recognise it

- File extensions: `.sr` (sigrok), `.logicdata`/`.sal` (Saleae), `.vcd` (Value Change
  Dump), `.csv` (exported samples), `.bin` (raw packed samples).
- `unzip -l cap.sr` shows `version`, `metadata`, `logic-1-1`, `logic-1-2`...
- The metadata file names the probes: `probe1=CLK`, `probe2=MOSI`, or just `D0`..`D7`.

## Theory

### The .sr container

```
version        ->  "2"
metadata       ->  INI-style:
                     [device 1]
                     capturefile = logic-1
                     total probes = 8
                     samplerate = 1 MHz
                     probe1 = D0
                     unitsize = 1
logic-1-1      ->  raw samples, `unitsize` bytes per sample, LSB = probe1
```

With `unitsize = 1`, each byte is one sample and bit `n` is channel `n`. The whole file
is therefore trivially parseable without sigrok (see the script below).

### Identifying channels

| Observation | Role |
|---|---|
| Highest toggle rate, near-perfect 50% duty, only active in bursts | CLK (SPI/I2C) |
| Idles high, goes low for the whole burst, one low per transaction | /CS (SPI) |
| Changes only while CLK is low, sampled on CLK edge | MOSI/MISO (SPI) |
| Idles high, has a high-to-low transition while the other line is high | SDA start condition (I2C) |
| Exactly two active channels, one is the clock | I2C (SCL + SDA) |
| One channel only, idles high, 10-bit frames | UART |
| One channel, long low pulses then short/long bit slots | 1-Wire |
| Idles high with open-drain slow rise (RC curve) | I2C or 1-Wire (pull-up) |

Count the channels first: 1 = UART or 1-Wire, 2 = I2C or SWD, 3-4 = SPI, 4-5 = JTAG.

### Sampling rate rule

You need at least 4x, ideally 10x, the bus clock. A 1 MHz SPI bus captured at 1 MHz is
undecodable. If the decoder produces nonsense, check
`samplerate / bus_clock` in the metadata.

### SPI modes

| Mode | CPOL | CPHA | Data sampled on |
|---|---|---|---|
| 0 | 0 | 0 | rising edge (clock idles low) |
| 1 | 0 | 1 | falling edge |
| 2 | 1 | 0 | falling edge (clock idles high) |
| 3 | 1 | 1 | rising edge |

Mode 0 covers most flash chips. If bytes look shifted by one bit, try the other CPHA.

## Attack

1. `sigrok-cli -i cap.sr --show` - sample rate, channel count, channel names.
2. Export a small slice to ASCII/CSV and eyeball which channel is the clock.
3. Run the matching decoder; if channel mapping is a guess, try permutations.
4. Read the decoded bytes; for SPI flash the first bytes are a command
   (`0x03` read, `0x9F` RDID) which confirms the mapping.
5. Extract the payload bytes, write them to a file, and treat that as firmware.

## Code

### sigrok-cli

```bash
# what is in the capture
sigrok-cli -i cap.sr --show
unzip -l cap.sr && unzip -p cap.sr metadata

# list every available decoder and its options
sigrok-cli -L | head -40
sigrok-cli --protocol-decoders | grep -iE 'spi|i2c|uart|onewire'
sigrok-cli -P spi --show
sigrok-cli -P i2c --show
sigrok-cli -P uart --show

# --- UART ---
sigrok-cli -i cap.sr -P uart:rx=D0:baudrate=115200 -A uart=rx-data
sigrok-cli -i cap.sr -P uart:rx=D0:tx=D1:baudrate=9600:format=ascii
sigrok-cli -i cap.sr -P uart:rx=D0:baudrate=115200:parity=none:data_bits=8:stop_bits=1

# --- SPI ---
sigrok-cli -i cap.sr \
  -P spi:clk=D0:mosi=D1:miso=D2:cs=D3:cpol=0:cpha=0:bitorder=msb-first \
  -A spi=mosi-data
sigrok-cli -i cap.sr -P spi:clk=D0:mosi=D1:miso=D2:cs=D3 -A spi=miso-data
# stacked decoder: spi -> spiflash gives you decoded flash commands
sigrok-cli -i cap.sr -P spi:clk=D0:mosi=D1:miso=D2:cs=D3,spiflash -A spiflash

# --- I2C ---
sigrok-cli -i cap.sr -P i2c:scl=D0:sda=D1 -A i2c
sigrok-cli -i cap.sr -P i2c:scl=D0:sda=D1 -A i2c=address-read:address-write:data-read:data-write
# stacked: i2c -> eeprom24xx decodes eeprom reads/writes
sigrok-cli -i cap.sr -P i2c:scl=D0:sda=D1,eeprom24xx -A eeprom24xx

# --- 1-Wire ---
sigrok-cli -i cap.sr -P onewire_link:owr=D0 -A onewire_link
sigrok-cli -i cap.sr -P onewire_link:owr=D0,onewire_network -A onewire_network

# --- other useful stacks ---
sigrok-cli -i cap.sr -P can:can_rx=D0:bitrate=500000 -A can
sigrok-cli -i cap.sr -P jtag:tck=D0:tms=D1:tdi=D2:tdo=D3 -A jtag
sigrok-cli -i cap.sr -P swd:swclk=D0:swdio=D1 -A swd
sigrok-cli -i cap.sr -P dmx512:dmx=D0 -A dmx512
sigrok-cli -i cap.sr -P ps2:clk=D0:data=D1 -A ps2

# --- exporting ---
sigrok-cli -i cap.sr -O ascii > waveform.txt         # ascii art, great for eyeballing
sigrok-cli -i cap.sr -O bits  | head -40
sigrok-cli -i cap.sr -O csv -o samples.csv           # for your own scripts
sigrok-cli -i cap.sr -O vcd -o cap.vcd               # for gtkwave
sigrok-cli -i cap.sr -O hex | head
sigrok-cli -i cap.sr --samples 2000 -O ascii         # just the first 2000 samples

# --- capturing ---
sigrok-cli --scan
sigrok-cli -d fx2lafw --config samplerate=8m --samples 8M -o cap.sr
sigrok-cli -d fx2lafw -c samplerate=24m --time 5s -o cap.sr
sigrok-cli -d fx2lafw -c samplerate=1m --continuous -o cap.sr
sigrok-cli -d fx2lafw -c samplerate=4m --triggers D3=f --samples 4M -o cap.sr  # falling CS
```

### PulseView (GUI) workflow

```text
1. File > Open  (or Ctrl-O) the .sr file
2. If the channels are unnamed, right-click a channel name to rename it
3. Zoom to a burst:  select with the mouse, or press 'z' / use the scroll wheel with Ctrl
4. Click "Add protocol decoder" (the green + icon), pick SPI / I2C / UART
5. Click the decoder's name to open its options: assign channels, set CPOL/CPHA/baud
6. Stack a second decoder on the first (e.g. SPI -> SPI flash) from the same menu
7. Right-click a decoded row > "Export all annotations" to get the bytes as text
8. Use cursors (the ruler icon) to measure a bit period -> baud = 1 / period
```

### Extracting the payload from decoded output

```bash
# sigrok prints one annotation per line; pull the hex bytes out
sigrok-cli -i cap.sr -P spi:clk=D0:mosi=D1:miso=D2:cs=D3 -A spi=miso-data \
  | grep -oE '0x[0-9A-Fa-f]{2}' | sed 's/0x//' | tr -d '\n' | xxd -r -p > payload.bin

file payload.bin && binwalk payload.bin
strings -n 6 payload.bin | head

# uart: get the ascii directly
sigrok-cli -i cap.sr -P uart:rx=D0:baudrate=115200:format=ascii -A uart=rx-data \
  | sed 's/^uart-1: rx-data: //' | tr -d '\n'

# i2c: separate the address from the data
sigrok-cli -i cap.sr -P i2c:scl=D0:sda=D1 -A i2c \
  | grep -E 'Address|Data' | head -40
```

### Pure-Python .sr reader and channel classifier

```python
#!/usr/bin/env python3
"""srread.py - read a sigrok .sr capture without sigrok, and guess channel roles.

Prints the metadata, per-channel statistics (toggle count, duty cycle, shortest
pulse) and a suggested role for each channel, then optionally exports CSV for the
decoders in scripts/hardware/protocol-decoders.md.

Usage:
  python3 srread.py cap.sr
  python3 srread.py cap.sr --csv samples.csv
"""
from __future__ import annotations

import configparser
import io
import sys
import zipfile


def read_sr(path: str) -> tuple[dict, list[str], list[int], int]:
    """Return (metadata, channel names, samples as ints, samplerate)."""
    with zipfile.ZipFile(path) as z:
        raw_meta = z.read("metadata").decode("utf-8", "replace")
        cp = configparser.ConfigParser()
        cp.read_file(io.StringIO(raw_meta))
        section = next(s for s in cp.sections() if s.startswith("device"))
        meta = dict(cp[section])

        unitsize = int(meta.get("unitsize", 1))
        rate_s = meta.get("samplerate", "1 MHz")
        samplerate = parse_rate(rate_s)

        names = []
        i = 1
        while f"probe{i}" in meta:
            names.append(meta[f"probe{i}"])
            i += 1
        if not names:
            names = [f"D{n}" for n in range(int(meta.get("total probes", 8)))]

        chunks = sorted(n for n in z.namelist() if n.startswith("logic-"))
        blob = b"".join(z.read(n) for n in chunks)

    samples: list[int] = []
    for off in range(0, len(blob) - unitsize + 1, unitsize):
        samples.append(int.from_bytes(blob[off:off + unitsize], "little"))
    return meta, names, samples, samplerate


def parse_rate(text: str) -> int:
    text = text.strip().lower().replace(" ", "")
    mult = 1
    for suffix, m in (("ghz", 10 ** 9), ("mhz", 10 ** 6), ("khz", 10 ** 3), ("hz", 1)):
        if text.endswith(suffix):
            mult = m
            text = text[: -len(suffix)]
            break
    try:
        return int(float(text) * mult)
    except ValueError:
        return 1_000_000


def channel_stats(samples: list[int], index: int) -> dict:
    bits = [(s >> index) & 1 for s in samples]
    n = len(bits)
    if n == 0:
        return {"toggles": 0, "duty": 0.0, "min_run": 0, "max_run": 0, "constant": True}
    toggles = sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    ones = sum(bits)
    runs = []
    run = 1
    for i in range(1, n):
        if bits[i] == bits[i - 1]:
            run += 1
        else:
            runs.append(run)
            run = 1
    runs.append(run)
    return {
        "toggles": toggles,
        "duty": ones / n,
        "min_run": min(runs),
        "max_run": max(runs),
        "constant": toggles == 0,
    }


def classify(stats: list[dict], samplerate: int) -> list[str]:
    roles = ["?"] * len(stats)
    active = [i for i, s in enumerate(stats) if not s["constant"]]
    if not active:
        return ["idle/unused"] * len(stats)

    # the clock is the channel with the most toggles and a near-50% duty cycle
    clk = max(active, key=lambda i: stats[i]["toggles"])
    roles[clk] = "CLK (most toggles)"

    for i in active:
        if i == clk:
            continue
        s = stats[i]
        if s["duty"] > 0.85 and s["toggles"] < stats[clk]["toggles"] / 8:
            roles[i] = "/CS or enable (idles high, few transitions)"
        elif s["toggles"] > stats[clk]["toggles"] / 4:
            roles[i] = "DATA (toggles with the clock)"
        else:
            roles[i] = "DATA or slow control"
    for i, s in enumerate(stats):
        if s["constant"]:
            roles[i] = "constant (unused / tied)"
    # single active channel -> uart or 1-wire
    if len(active) == 1:
        s = stats[active[0]]
        est = samplerate / max(1, s["min_run"])
        roles[active[0]] = f"single line: UART or 1-Wire (est. bitrate {est:.0f} bps)"
    return roles


def report(path: str, csv_out: str | None = None) -> None:
    meta, names, samples, rate = read_sr(path)
    print(f"== {path}")
    print(f"samplerate : {rate} Hz")
    print(f"samples    : {len(samples)}")
    print(f"duration   : {len(samples)/rate*1000:.3f} ms")
    print(f"channels   : {', '.join(names)}")

    stats = [channel_stats(samples, i) for i in range(len(names))]
    roles = classify(stats, rate)
    print("\nch   name      toggles    duty   min_run  est_clk_hz  role")
    for i, name in enumerate(names):
        s = stats[i]
        est = rate / (2 * s["min_run"]) if s["min_run"] else 0
        print(f"{i:<4} {name:<9} {s['toggles']:>8}  {s['duty']:6.2%}  "
              f"{s['min_run']:>7}  {est:>10.0f}  {roles[i]}")

    print("\nsuggested sigrok-cli commands:")
    clk = max(range(len(stats)), key=lambda i: stats[i]["toggles"])
    active = [i for i, s in enumerate(stats) if not s["constant"]]
    if len(active) == 1:
        print(f"  sigrok-cli -i {path} -P uart:rx={names[active[0]]}:baudrate=115200 -A uart")
    elif len(active) == 2:
        other = [i for i in active if i != clk][0]
        print(f"  sigrok-cli -i {path} -P i2c:scl={names[clk]}:sda={names[other]} -A i2c")
    else:
        rest = [names[i] for i in active if i != clk]
        pins = ":".join(f"{p}={n}" for p, n in zip(("mosi", "miso", "cs"), rest))
        print(f"  sigrok-cli -i {path} -P spi:clk={names[clk]}:{pins} -A spi")

    if csv_out:
        with open(csv_out, "w", encoding="utf-8") as fh:
            fh.write("sample," + ",".join(names) + "\n")
            for idx, s in enumerate(samples):
                bits = ",".join(str((s >> i) & 1) for i in range(len(names)))
                fh.write(f"{idx},{bits}\n")
        print(f"\nwrote {csv_out}")


def _make_test_sr(path: str) -> None:
    """Build a tiny synthetic .sr: D0 = clock, D1 = data, D2 = chip select."""
    samples = bytearray()
    for byte_i in range(4):
        # cs low for the whole byte
        for bit in range(8):
            data = (0xA5 >> (7 - bit)) & 1
            for phase in (0, 1):
                val = (phase << 0) | (data << 1) | (0 << 2)
                samples.append(val)
        samples.extend([0b100] * 4)          # cs high between bytes
    meta = ("[global]\nsigrok version=0.5.2\n"
            "[device 1]\ncapturefile=logic-1\ntotal probes=3\n"
            "samplerate=1 MHz\nprobe1=D0\nprobe2=D1\nprobe3=D2\nunitsize=1\n")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("version", "2")
        z.writestr("metadata", meta)
        z.writestr("logic-1-1", bytes(samples))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    csv_out = None
    if "--csv" in argv:
        csv_out = argv[argv.index("--csv") + 1]
    report(argv[1], csv_out)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "test.sr")
            _make_test_sr(p)
            meta, names, samples, rate = read_sr(p)
            assert names == ["D0", "D1", "D2"], names
            assert rate == 1_000_000, rate
            assert len(samples) > 0
            stats = [channel_stats(samples, i) for i in range(3)]
            assert stats[0]["toggles"] > stats[2]["toggles"], stats
            report(p, os.path.join(d, "out.csv"))
            assert os.path.exists(os.path.join(d, "out.csv"))
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

## Variants & pitfalls

- **Decoder outputs nothing** - the channel mapping is wrong, or the sample rate is too
  low. Try every clock candidate; SPI has only a few permutations.
- **Bytes are bit-shifted** - wrong CPHA. Flip it and re-run.
- **Bytes are reversed** - `bitorder=lsb-first` (rare on SPI, normal on UART internals).
- **I2C shows only addresses, no data** - SDA and SCL are swapped.
- **Glitchy edges** - the capture is under-sampled or the probe ground is poor. Sigrok
  cannot fix it; re-capture at a higher rate with a short ground lead.
- **Saleae `.logicdata`** is not directly readable by sigrok. Export CSV/VCD from the
  Saleae software, or use `sigrok-cli -I csv`.
- **`.vcd` import** needs `-I vcd:downsample=...` and explicit channel naming.

## Tools

- `sigrok-cli` - scriptable capture, decode and export.
- `PulseView` - the GUI, best for identifying channels by eye.
- `fx2lafw`-based 8-channel analysers (very cheap), Saleae Logic, DSLogic.
- `gtkwave` - for `.vcd` inspection.
- The decoders bundled with libsigrokdecode: `spi`, `i2c`, `uart`, `onewire_link`,
  `can`, `jtag`, `swd`, `spiflash`, `eeprom24xx`, `ps2`, `dmx512`, `modbus`.

## References

- sigrok wiki: file format documentation for the `.sr` container and decoder options.
- libsigrokdecode documentation for the decoder API and annotation classes.
- PulseView user manual for cursors, stacking and annotation export.
