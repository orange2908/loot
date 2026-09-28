---
title: "Protocol Decoders - SPI, I2C and UART from Raw Logic Samples in Python"
category: hardware
subcategory: logic-analysis
type: script
tags: [spi, i2c, uart, decoder, sigrok, csv, logic-analyzer, pulseview, bit-banging, cpol, cpha, ack-nack, start-condition, saleae, python]
summary: "Standalone Python that decodes SPI, I2C and UART from a CSV of logic-analyzer samples, with no sigrok dependency."
tools: [python, sigrok-cli, pulseview]
related: [logic-analyzer-decoding, uart-baud-scanner, uart-serial, spi-i2c-flash-dump]
---

## What it does

Takes a CSV of digital samples (the format `sigrok-cli -O csv` and Saleae both export)
and decodes it as SPI, I2C or UART, printing the recovered bytes as hex and ASCII.

Everything is stdlib. It is deliberately simple to adapt: each decoder is a single
function taking lists of `0`/`1` per channel plus the sample rate.

## Input format

```
sample,D0,D1,D2,D3
0,1,0,1,1
1,1,0,1,1
2,0,0,1,1
...
```

A leading index column is optional and auto-detected. Channel names can be anything;
you select them by name or by position.

Produce one with:

```bash
# from a sigrok capture
sigrok-cli -i cap.sr -O csv -o samples.csv
sigrok-cli -i cap.sr -O csv --samples 200000 -o samples.csv

# from Saleae Logic: File > Export Data > CSV, "digital", no time column needed
# (if it exports a time column instead of an index, pass --time-column)
```

## Usage

```bash
# see what is in the file and let it guess the channel roles
python3 protocol_decoders.py samples.csv --rate 1000000 --info

# SPI: mode 0, MSB first
python3 protocol_decoders.py samples.csv --rate 1000000 \
    spi --clk D0 --mosi D1 --miso D2 --cs D3 --cpol 0 --cpha 0

# I2C
python3 protocol_decoders.py samples.csv --rate 1000000 i2c --scl D0 --sda D1

# UART at a known rate, or let it estimate one
python3 protocol_decoders.py samples.csv --rate 1000000 uart --rx D0 --baud 115200
python3 protocol_decoders.py samples.csv --rate 1000000 uart --rx D0 --auto-baud

# write the recovered payload to a file for binwalk
python3 protocol_decoders.py samples.csv --rate 1000000 \
    spi --clk D0 --mosi D1 --miso D2 --cs D3 --out miso.bin --which miso
```

## Script

```python
#!/usr/bin/env python3
"""protocol_decoders.py - decode SPI, I2C and UART from raw logic-analyzer samples.

Reads a CSV of digital channel values (one row per sample) and decodes the selected
bus. No sigrok, numpy or other dependencies.

Run with no arguments to execute a self-test that synthesises each bus, decodes it
and asserts the payload round-trips.
"""
from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# sample loading
# ---------------------------------------------------------------------------
@dataclass
class Capture:
    names: list[str]
    channels: dict[str, list[int]]
    samplerate: int

    @property
    def length(self) -> int:
        return len(next(iter(self.channels.values()))) if self.channels else 0

    def get(self, name: str) -> list[int]:
        if name in self.channels:
            return self.channels[name]
        # allow selection by index: "0" means the first data channel
        if name.isdigit() and int(name) < len(self.names):
            return self.channels[self.names[int(name)]]
        raise KeyError(f"no such channel {name!r}; have {', '.join(self.names)}")


def load_csv(path: str, samplerate: int, time_column: bool = False) -> Capture:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(r for r in fh if not r.lstrip().startswith(";")))
    if not rows:
        raise ValueError("empty csv")

    header = rows[0]
    has_header = any(not _is_number(c) for c in header)
    data_rows = rows[1:] if has_header else rows
    names = [c.strip() for c in header] if has_header else \
            [f"D{i}" for i in range(len(header))]

    # drop a leading index/time column if present
    drop_first = time_column
    if not drop_first and len(names) > 1:
        first_vals = {r[0].strip() for r in data_rows[:20] if r}
        if not first_vals <= {"0", "1"}:
            drop_first = True
    if drop_first:
        names = names[1:]

    channels: dict[str, list[int]] = {n: [] for n in names}
    for row in data_rows:
        if not row:
            continue
        vals = row[1:] if drop_first else row
        if len(vals) < len(names):
            continue
        for n, v in zip(names, vals):
            s = v.strip()
            channels[n].append(1 if s not in ("0", "", "0.0", "false", "False") else 0)
    return Capture(names, channels, samplerate)


def _is_number(s: str) -> bool:
    try:
        float(s.strip())
        return True
    except ValueError:
        return False


def edges(sig: list[int], rising: bool = True) -> list[int]:
    out = []
    for i in range(1, len(sig)):
        if rising and sig[i - 1] == 0 and sig[i] == 1:
            out.append(i)
        elif not rising and sig[i - 1] == 1 and sig[i] == 0:
            out.append(i)
    return out


# ---------------------------------------------------------------------------
# SPI
# ---------------------------------------------------------------------------
@dataclass
class SpiTransfer:
    start: int
    mosi: bytes = b""
    miso: bytes = b""


def decode_spi(clk: list[int], mosi: list[int] | None, miso: list[int] | None,
               cs: list[int] | None = None, cpol: int = 0, cpha: int = 0,
               msb_first: bool = True, cs_active_low: bool = True
               ) -> list[SpiTransfer]:
    """Sample MOSI/MISO on the active clock edge, grouping bytes by chip select."""
    # CPOL=0,CPHA=0 and CPOL=1,CPHA=1 sample on the leading edge (rising for CPOL=0)
    sample_on_rising = (cpol == cpha)
    sample_edges = edges(clk, rising=sample_on_rising)

    transfers: list[SpiTransfer] = []
    current: SpiTransfer | None = None
    bit_count = 0
    mo_acc = 0
    mi_acc = 0

    def cs_active(i: int) -> bool:
        if cs is None:
            return True
        return (cs[i] == 0) if cs_active_low else (cs[i] == 1)

    prev_active = False
    for idx in sample_edges:
        active = cs_active(idx)
        if active and not prev_active:
            current = SpiTransfer(start=idx)
            transfers.append(current)
            bit_count = mo_acc = mi_acc = 0
        prev_active = active
        if not active:
            continue
        if current is None:
            current = SpiTransfer(start=idx)
            transfers.append(current)

        mo_bit = mosi[idx] if mosi else 0
        mi_bit = miso[idx] if miso else 0
        if msb_first:
            mo_acc = (mo_acc << 1) | mo_bit
            mi_acc = (mi_acc << 1) | mi_bit
        else:
            mo_acc |= mo_bit << bit_count
            mi_acc |= mi_bit << bit_count
        bit_count += 1
        if bit_count == 8:
            current.mosi += bytes([mo_acc & 0xFF])
            current.miso += bytes([mi_acc & 0xFF])
            bit_count = mo_acc = mi_acc = 0

    return [t for t in transfers if t.mosi or t.miso]


# ---------------------------------------------------------------------------
# I2C
# ---------------------------------------------------------------------------
@dataclass
class I2cTransaction:
    start: int
    address: int = 0
    read: bool = False
    data: bytes = b""
    acks: list[bool] = field(default_factory=list)
    addr_ack: bool = False


def decode_i2c(scl: list[int], sda: list[int]) -> list[I2cTransaction]:
    """Track START/STOP conditions and sample SDA on every SCL rising edge."""
    txs: list[I2cTransaction] = []
    cur: I2cTransaction | None = None
    bits: list[int] = []
    first_byte = True

    n = min(len(scl), len(sda))
    for i in range(1, n):
        # START: SDA falls while SCL is high. STOP: SDA rises while SCL is high.
        if scl[i] == 1 and scl[i - 1] == 1:
            if sda[i - 1] == 1 and sda[i] == 0:
                cur = I2cTransaction(start=i)
                txs.append(cur)
                bits = []
                first_byte = True
                continue
            if sda[i - 1] == 0 and sda[i] == 1:
                cur = None
                bits = []
                continue

        if cur is None:
            continue

        # data bits are valid on the SCL rising edge
        if scl[i] == 1 and scl[i - 1] == 0:
            bits.append(sda[i])
            if len(bits) == 9:
                value = 0
                for b in bits[:8]:
                    value = (value << 1) | b
                ack = bits[8] == 0        # ACK is SDA pulled low
                if first_byte:
                    cur.address = value >> 1
                    cur.read = bool(value & 1)
                    cur.addr_ack = ack
                    first_byte = False
                else:
                    cur.data += bytes([value])
                    cur.acks.append(ack)
                bits = []
    return txs


# ---------------------------------------------------------------------------
# UART
# ---------------------------------------------------------------------------
def estimate_baud(sig: list[int], samplerate: int) -> int:
    """Shortest run length is one bit time."""
    runs: list[int] = []
    run = 1
    for i in range(1, len(sig)):
        if sig[i] == sig[i - 1]:
            run += 1
        else:
            runs.append(run)
            run = 1
    runs.append(run)
    meaningful = sorted(r for r in runs if r > 1)
    if not meaningful:
        return 0
    shortest = meaningful[max(0, len(meaningful) // 20)]
    return int(round(samplerate / shortest))


def decode_uart(sig: list[int], samplerate: int, baud: int, data_bits: int = 8,
                parity: str = "N", stop_bits: int = 1, invert: bool = False,
                lsb_first: bool = True) -> tuple[bytes, list[str]]:
    """Sample the middle of each bit cell after every detected start bit."""
    if baud <= 0:
        return b"", ["baud rate must be positive"]
    samples_per_bit = samplerate / baud
    if samples_per_bit < 2:
        return b"", [f"sample rate too low: {samples_per_bit:.2f} samples per bit"]

    line = [1 - v for v in sig] if invert else list(sig)
    out = bytearray()
    errors: list[str] = []
    i = 1
    n = len(line)

    while i < n:
        # find a falling edge = start bit
        if not (line[i - 1] == 1 and line[i] == 0):
            i += 1
            continue
        start = i
        # verify the start bit is still low at its midpoint
        mid_start = start + samples_per_bit / 2.0
        if int(mid_start) >= n or line[int(mid_start)] != 0:
            i += 1
            continue

        value = 0
        ok = True
        for bit in range(data_bits):
            pos = int(start + samples_per_bit * (bit + 1.5))
            if pos >= n:
                ok = False
                break
            b = line[pos]
            if lsb_first:
                value |= b << bit
            else:
                value = (value << 1) | b
        if not ok:
            break

        # bit cell index of the next field, counting the start bit as cell 0
        cell = data_bits + 1
        has_parity = parity in ("E", "O")
        if has_parity:
            pos = int(start + samples_per_bit * (cell + 0.5))
            if pos < n:
                ones = bin(value).count("1")
                want = (ones % 2) if parity == "E" else (1 - ones % 2)
                if line[pos] != want:
                    errors.append(f"parity error at sample {start}")
            cell += 1

        stop_pos = int(start + samples_per_bit * (cell + 0.5))
        if stop_pos < n and line[stop_pos] != 1:
            errors.append(f"framing error at sample {start}")

        out.append(value & 0xFF)
        # jump to the end of the frame: start + (1 start + data + parity + stop) cells,
        # which lands exactly on the next start-bit edge
        total_cells = 1 + data_bits + (1 if has_parity else 0) + stop_bits
        i = int(start + samples_per_bit * total_cells)
    return bytes(out), errors


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def ascii_of(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def describe_channels(cap: Capture) -> None:
    print(f"{cap.length} samples at {cap.samplerate} Hz "
          f"({cap.length / max(1, cap.samplerate):.4f} s)")
    print(f"{'channel':<10} {'toggles':>8} {'duty':>7} {'min_run':>8}  guess")
    best_clk = None
    best_toggles = -1
    stats = {}
    for name in cap.names:
        sig = cap.channels[name]
        toggles = sum(1 for i in range(1, len(sig)) if sig[i] != sig[i - 1])
        duty = sum(sig) / max(1, len(sig))
        runs = []
        run = 1
        for i in range(1, len(sig)):
            if sig[i] == sig[i - 1]:
                run += 1
            else:
                runs.append(run)
                run = 1
        runs.append(run)
        min_run = min(runs) if runs else 0
        stats[name] = (toggles, duty, min_run)
        if toggles > best_toggles:
            best_toggles, best_clk = toggles, name

    for name in cap.names:
        toggles, duty, min_run = stats[name]
        if toggles == 0:
            guess = "constant (tied/unused)"
        elif name == best_clk:
            guess = "CLK / SCL (most transitions)"
        elif duty > 0.85 and toggles < best_toggles / 8:
            guess = "/CS or enable (idles high)"
        else:
            guess = "DATA"
        print(f"{name:<10} {toggles:>8} {duty:>6.1%} {min_run:>8}  {guess}")

    active = [n for n in cap.names if stats[n][0] > 0]
    if len(active) == 1:
        est = estimate_baud(cap.channels[active[0]], cap.samplerate)
        print(f"\nsingle active channel -> UART, estimated {est} baud")
    elif len(active) == 2:
        print("\ntwo active channels -> I2C (SCL + SDA)")
    elif len(active) >= 3:
        print("\nthree or more active channels -> SPI")


def main() -> int:
    ap = argparse.ArgumentParser(description="decode SPI/I2C/UART from logic samples")
    ap.add_argument("csvfile")
    ap.add_argument("--rate", type=int, required=True, help="sample rate in Hz")
    ap.add_argument("--time-column", action="store_true",
                    help="first column is a timestamp, not a channel")
    ap.add_argument("--info", action="store_true", help="describe channels and exit")
    ap.add_argument("--out", help="write the decoded payload to this file")
    ap.add_argument("--which", default="mosi", choices=["mosi", "miso", "data"],
                    help="which stream --out should write")

    sub = ap.add_subparsers(dest="proto")

    p_spi = sub.add_parser("spi")
    p_spi.add_argument("--clk", required=True)
    p_spi.add_argument("--mosi")
    p_spi.add_argument("--miso")
    p_spi.add_argument("--cs")
    p_spi.add_argument("--cpol", type=int, default=0, choices=[0, 1])
    p_spi.add_argument("--cpha", type=int, default=0, choices=[0, 1])
    p_spi.add_argument("--lsb-first", action="store_true")

    p_i2c = sub.add_parser("i2c")
    p_i2c.add_argument("--scl", required=True)
    p_i2c.add_argument("--sda", required=True)

    p_uart = sub.add_parser("uart")
    p_uart.add_argument("--rx", required=True)
    p_uart.add_argument("--baud", type=int, default=0)
    p_uart.add_argument("--auto-baud", action="store_true")
    p_uart.add_argument("--data-bits", type=int, default=8)
    p_uart.add_argument("--parity", default="N", choices=["N", "E", "O"])
    p_uart.add_argument("--stop-bits", type=int, default=1)
    p_uart.add_argument("--invert", action="store_true")

    args = ap.parse_args()
    cap = load_csv(args.csvfile, args.rate, args.time_column)

    if args.info or not args.proto:
        describe_channels(cap)
        return 0

    payload = b""
    if args.proto == "spi":
        transfers = decode_spi(
            cap.get(args.clk),
            cap.get(args.mosi) if args.mosi else None,
            cap.get(args.miso) if args.miso else None,
            cap.get(args.cs) if args.cs else None,
            args.cpol, args.cpha, not args.lsb_first)
        print(f"{len(transfers)} SPI transfer(s)")
        mo = bytearray()
        mi = bytearray()
        for t in transfers:
            print(f"\n-- transfer at sample {t.start} --")
            if t.mosi:
                print(f"  MOSI: {t.mosi.hex(' ')}  |{ascii_of(t.mosi)}|")
                mo += t.mosi
            if t.miso:
                print(f"  MISO: {t.miso.hex(' ')}  |{ascii_of(t.miso)}|")
                mi += t.miso
        payload = bytes(mo if args.which == "mosi" else mi)

    elif args.proto == "i2c":
        txs = decode_i2c(cap.get(args.scl), cap.get(args.sda))
        print(f"{len(txs)} I2C transaction(s)")
        acc = bytearray()
        for t in txs:
            rw = "READ" if t.read else "WRITE"
            print(f"\n-- start at sample {t.start} --")
            print(f"  address 0x{t.address:02x} {rw} "
                  f"{'ACK' if t.addr_ack else 'NAK'}")
            if t.data:
                print(f"  data: {t.data.hex(' ')}  |{ascii_of(t.data)}|")
                print(f"  acks: {''.join('A' if a else 'N' for a in t.acks)}")
                acc += t.data
        payload = bytes(acc)

    elif args.proto == "uart":
        sig = cap.get(args.rx)
        baud = args.baud
        if args.auto_baud or not baud:
            baud = estimate_baud(sig, cap.samplerate)
            print(f"estimated baud: {baud}")
        data, errors = decode_uart(sig, cap.samplerate, baud, args.data_bits,
                                   args.parity, args.stop_bits, args.invert)
        print(f"{len(data)} byte(s), {len(errors)} error(s)")
        for e in errors[:10]:
            print("  " + e)
        print("\nhex   : " + data.hex(" "))
        print("ascii : " + data.decode("utf-8", "replace"))
        payload = data

    if args.out and payload:
        with open(args.out, "wb") as fh:
            fh.write(payload)
        print(f"\nwrote {len(payload)} bytes to {args.out}")
    return 0


# ---------------------------------------------------------------------------
# self-test: synthesise each bus, decode it, assert the payload round-trips
# ---------------------------------------------------------------------------
def _synth_spi(payload_mosi: bytes, payload_miso: bytes, sps: int = 4):
    clk, mosi, miso, cs = [], [], [], []

    def push(c, mo, mi, s, n=sps):
        clk.extend([c] * n)
        mosi.extend([mo] * n)
        miso.extend([mi] * n)
        cs.extend([s] * n)

    push(0, 0, 0, 1, sps * 4)                      # idle, cs high
    for bo, bi in zip(payload_mosi, payload_miso):
        for bit in range(7, -1, -1):
            mo = (bo >> bit) & 1
            mi = (bi >> bit) & 1
            push(0, mo, mi, 0)                     # set data while clk low
            push(1, mo, mi, 0)                     # rising edge samples it
    push(0, 0, 0, 1, sps * 4)
    return clk, mosi, miso, cs


def _synth_i2c(address: int, read: bool, payload: bytes, sps: int = 4):
    scl, sda = [], []

    def push(c, d, n=sps):
        scl.extend([c] * n)
        sda.extend([d] * n)

    push(1, 1, sps * 4)                            # idle
    push(1, 0, sps)                                # START: sda falls while scl high
    for value, ack in [((address << 1) | int(read), 0)] + [(b, 0) for b in payload]:
        for bit in range(7, -1, -1):
            d = (value >> bit) & 1
            push(0, d)
            push(1, d)
        push(0, ack)                               # ack bit
        push(1, ack)
    push(0, 0, sps)
    push(1, 0, sps)
    push(1, 1, sps * 4)                            # STOP: sda rises while scl high
    return scl, sda


def _synth_uart(payload: bytes, sps: int = 16):
    sig = [1] * (sps * 4)
    for byte in payload:
        sig.extend([0] * sps)                      # start bit
        for bit in range(8):
            sig.extend([(byte >> bit) & 1] * sps)  # lsb first
        sig.extend([1] * sps)                      # stop bit
    sig.extend([1] * (sps * 4))
    return sig


def _selftest() -> None:
    # --- SPI ---
    want_mo = bytes.fromhex("039F0000")
    want_mi = b"hsqs"
    clk, mosi, miso, cs = _synth_spi(want_mo, want_mi)
    transfers = decode_spi(clk, mosi, miso, cs, cpol=0, cpha=0)
    assert len(transfers) == 1, len(transfers)
    assert transfers[0].mosi == want_mo, transfers[0].mosi.hex()
    assert transfers[0].miso == want_mi, transfers[0].miso
    print(f"SPI  ok: MOSI={transfers[0].mosi.hex(' ')} MISO={transfers[0].miso!r}")

    # SPI without chip select still decodes
    t2 = decode_spi(clk, mosi, miso, None, cpol=0, cpha=0)
    assert t2 and want_mi in t2[0].miso, t2[0].miso

    # --- I2C ---
    scl, sda = _synth_i2c(0x50, False, b"flag")
    txs = decode_i2c(scl, sda)
    assert len(txs) == 1, len(txs)
    assert txs[0].address == 0x50, hex(txs[0].address)
    assert txs[0].read is False
    assert txs[0].data == b"flag", txs[0].data
    assert all(txs[0].acks), txs[0].acks
    print(f"I2C  ok: addr=0x{txs[0].address:02x} data={txs[0].data!r}")

    # --- UART ---
    msg = b"U-Boot 2016.05\r\n"
    sig = _synth_uart(msg, sps=16)
    rate = 16 * 115200
    est = estimate_baud(sig, rate)
    assert abs(est - 115200) / 115200 < 0.05, est
    data, errors = decode_uart(sig, rate, 115200)
    assert data == msg, (data, msg)
    assert not errors, errors
    print(f"UART ok: est={est} baud, decoded {data!r}")

    # --- CSV round trip through the loader ---
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "s.csv")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("sample,D0,D1,D2,D3\n")
            for i in range(len(clk)):
                fh.write(f"{i},{clk[i]},{mosi[i]},{miso[i]},{cs[i]}\n")
        cap = load_csv(p, 1_000_000)
        assert cap.names == ["D0", "D1", "D2", "D3"], cap.names
        assert cap.length == len(clk), (cap.length, len(clk))
        t3 = decode_spi(cap.get("D0"), cap.get("D1"), cap.get("D2"), cap.get("D3"))
        assert t3[0].miso == want_mi, t3[0].miso
        describe_channels(cap)
    print("\nselftest ok")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _selftest()
    else:
        sys.exit(main())
```

## Notes

- **SPI mode**: `cpol == cpha` means the data is sampled on the *rising* edge
  (modes 0 and 3). If bytes come out shifted by one bit, flip `--cpha`.
- **SPI without CS** works, but you lose transfer boundaries: bytes run together and a
  missed clock edge shifts everything after it. Always wire CS if you can.
- **I2C ACK polarity**: ACK is SDA pulled *low* by the receiver. A transaction full of
  NAKs usually means SCL and SDA are swapped.
- **UART needs >= 4 samples per bit**, and 8-16 is comfortable. The decoder refuses
  below 2 and tells you so.
- **`--auto-baud`** takes the 5th-percentile run length rather than the strict minimum,
  so a single glitch does not skew the estimate.
- For very large CSVs, slice first: `sigrok-cli -i cap.sr -O csv --samples 500000`.
- If you already have sigrok installed, its decoders are faster and handle more edge
  cases. This script exists for the offline case where all you got was a CSV.
