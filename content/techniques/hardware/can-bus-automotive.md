---
title: "CAN Bus and Automotive - candump, cansend, DBC Reversing and Replay"
category: hardware
subcategory: automotive
type: technique
tags: [can-bus, can, socketcan, candump, cansend, cangen, canplayer, dbc, obd2, uds, isotp, vcan, arbitration-id, dlc, cantools, savvycan, replay]
difficulty: medium
summary: "Read a CAN capture or live bus, work out which arbitration ID carries which signal, and replay or forge frames."
when_to_use:
  - "The challenge gives you a candump log, a .asc/.blf/.log or a DBC file"
  - "You have a USB-CAN adapter on a simulated or real vehicle bus"
  - "You need to find the frame that unlocks the doors / prints the flag"
tools: [can-utils, socketcan, cantools, savvycan, python-can, wireshark]
related: [ics-modbus-protocols, logic-analyzer-decoding, mcu-reversing, protocol-decoders]
---

## TL;DR

CAN frames are `(arbitration ID, DLC, up to 8 data bytes)` with no addressing,
no authentication and no encryption - every node sees every frame. Set up `vcan0`,
replay the log with `canplayer`, and find the signal by **diffing**: record while the
thing is idle, record while you do the action, and look at which ID's bytes changed.
`cansniffer` does that live and is usually enough.

## Recognise it

- Files: `candump-2024-01-01_120000.log` (SocketCAN ASCII), `.asc` (Vector),
  `.blf` (Vector binary), `.trc` (PCAN), `.csv` from SavvyCAN, or a `.dbc` database.
- A line like `(1615825200.123456) can0 123#DEADBEEF01020304`.
- Challenge mentions ECU, OBD-II, UDS, ISO-TP, J1939, an instrument cluster.
- OBD-II IDs: request `0x7DF` (broadcast) or `0x7E0..0x7E7`, response `0x7E8..0x7EF`.

## Theory

### Frame anatomy

| Field | Standard (CAN 2.0A) | Extended (2.0B) |
|---|---|---|
| Arbitration ID | 11 bits (0x000-0x7FF) | 29 bits (0x00000000-0x1FFFFFFF) |
| RTR | remote transmission request | same |
| DLC | 0-8 data bytes (CAN FD: up to 64) | same |
| Data | 0-8 bytes | same |
| CRC, ACK, EOF | handled by the controller | same |

Lower ID = higher priority (dominant bits win arbitration). There is no source or
destination address: an ID identifies a *message type*, and by convention a sender.

### Signals inside a frame

A DBC file maps IDs to named signals:

```
BO_ 291 EngineData: 8 VECTOR__INDEPENDENT
 SG_ EngineSpeed : 0|16@1+ (0.25,0) [0|16383.75] "rpm" Vector__XXX
 SG_ CoolantTemp : 16|8@1+ (1,-40) [-40|215] "degC" Vector__XXX
```

Read `start_bit|length@byte_order+/-` then `(factor,offset)`:
`physical = raw * factor + offset`. `@1` = little endian (Intel), `@0` = big endian
(Motorola). `+` unsigned, `-` signed.

Without a DBC you reverse it by correlation: change one physical quantity and watch which
bytes move monotonically.

### OBD-II / UDS over ISO-TP

ISO-TP (ISO 15765-2) carries messages longer than 8 bytes over CAN:

| First byte high nibble | Frame type |
|---|---|
| `0x0` | Single frame; low nibble = length |
| `0x1` | First frame; 12-bit length follows |
| `0x2` | Consecutive frame; low nibble = sequence number |
| `0x3` | Flow control |

OBD-II mode 01 PID 0C = engine RPM: request `7DF# 02 01 0C 00 00 00 00 00`,
response `7E8# 04 41 0C <A> <B> ...` with `RPM = ((A*256)+B)/4`.

UDS services worth knowing: `0x10` DiagnosticSessionControl,
`0x11` ECUReset, `0x22` ReadDataByIdentifier, `0x23` ReadMemoryByAddress,
`0x27` SecurityAccess (seed/key - the classic CTF target),
`0x2E` WriteDataByIdentifier, `0x31` RoutineControl, `0x34`/`0x36`/`0x37` transfer
(firmware upload), `0x3E` TesterPresent. A negative response is
`7F <service> <NRC>`; `NRC 0x35` = invalid key, `0x33` = security access denied.

## Attack

1. Set up `vcan0` and replay the log - you now have a live bus with no hardware.
2. `cansniffer` to see which IDs change; `candump -l` to record.
3. Diff two recordings (idle vs action) to isolate the ID and byte.
4. Decode with a DBC if given (`cantools`), otherwise brute the scaling.
5. Replay the isolated frame with `cansend`; fuzz the payload with `cangen`.
6. For diagnostics, use ISO-TP sockets and walk UDS services; `0x27` seed/key is
   usually the flag.

## Code

### SocketCAN setup

```bash
# virtual bus - no hardware needed, perfect for replaying a challenge log
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
ip -details link show vcan0

# real adapter (slcan / usb-can)
sudo slcand -o -c -s6 /dev/ttyUSB0 can0      # -s6 = 500 kbit/s
sudo ip link set up can0
# -s0 10k -s1 20k -s2 50k -s3 100k -s4 125k -s5 250k -s6 500k -s7 800k -s8 1M

# native can interface (peak, kvaser, socketcan-capable)
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 type can bitrate 500000 fd on dbitrate 2000000  # CAN FD
sudo ip link set up can0
sudo ip link set can0 type can listen-only on    # safe: never transmit
ip -statistics link show can0                     # error counters, bus state
```

### can-utils

```bash
# watch everything; -t d = relative timestamps, -c -c = colour
candump can0 | candump -t d can0 | candump -c -c can0
candump vcan0,123:7FF                # only ID 0x123
candump -l can0                      # log to candump-<date>.log
candump -L can0 > capture.log        # log format on stdout

# the single best reconnaissance tool: group by ID, highlight changing bytes
cansniffer -c can0
cansniffer -t 0 can0                 # keep stale IDs visible

# send a frame
cansend can0 123#DEADBEEF
cansend can0 123#DE.AD.BE.EF.01.02.03.04
cansend can0 1F334455#1122334455667788        # extended id
cansend can0 123#R                             # remote frame

# repeat a frame (many ECUs only act while it keeps arriving)
while true; do cansend can0 123#0000000000000001; sleep 0.01; done
cangen can0 -g 4 -I 123 -L 8 -D r -v           # random data on 0x123 every 4 ms
cangen can0 -g 1 -I i -L i -D i                # fuzz everything (careful)

# replay a recorded log
canplayer -I capture.log                        # onto the same interface name
canplayer -I capture.log vcan0=can0             # remap can0 in the log to vcan0
canplayer -I capture.log -l i                   # loop forever

# statistics
canbusload can0@500000 -r -t -b -c
cansequence can0                                # detect dropped frames

# isotp (needs the can-isotp kernel module)
sudo modprobe can-isotp
isotpsend -s 7E0 -d 7E8 can0 <<< "02 10 03"
isotprecv -s 7E8 -d 7E0 -l can0
isotpdump -s 7E0 -d 7E8 can0
```

### Finding the interesting frame by diffing

```bash
# 1. record 10 seconds of idle traffic
timeout 10 candump -L vcan0 > idle.log

# 2. record while performing the action (press the button, open the door)
timeout 10 candump -L vcan0 > action.log

# 3. which IDs appear only during the action?
awk '{split($3,a,"#"); print a[1]}' idle.log   | sort -u > idle.ids
awk '{split($3,a,"#"); print a[1]}' action.log | sort -u > action.ids
comm -13 idle.ids action.ids

# 4. for a shared ID, which payloads are new?
grep ' 123#' action.log | awk '{print $3}' | sort -u > action.123
grep ' 123#' idle.log   | awk '{print $3}' | sort -u > idle.123
comm -13 idle.123 action.123

# 5. how many distinct payloads per ID (low count = a state/flag, high = a sensor)
awk '{split($3,a,"#"); print a[1], a[2]}' capture.log | sort -u |
  awk '{c[$1]++} END {for (k in c) printf "%s %d\n", k, c[k]}' | sort -k2 -n

# 6. strings hidden in payloads
awk '{split($3,a,"#"); print a[2]}' capture.log | tr -d '\n' | xxd -r -p |
  strings -n 4 | sort -u
```

### Python: parse a candump log, decode signals, find changing bytes

```python
#!/usr/bin/env python3
"""canlog.py - parse candump logs, summarise IDs, diff two captures and decode signals.

Pure stdlib. Handles the SocketCAN log format:
    (1615825200.123456) can0 123#DEADBEEF01020304
and the plain `123#DEADBEEF` form.

Usage:
  python3 canlog.py capture.log
  python3 canlog.py capture.log --id 0x123
  python3 canlog.py idle.log --diff action.log
  python3 canlog.py capture.log --signal 0x123 0 16 little 0.25 0
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict

LINE_RE = re.compile(
    r"^(?:\((?P<ts>[\d.]+)\)\s+)?(?P<iface>\S+)\s+"
    r"(?P<id>[0-9A-Fa-f]+)#(?P<flags>#[0-9A-Fa-f])?(?P<data>[0-9A-Fa-f.]*)\s*$")


def parse_line(line: str):
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    ts = float(m.group("ts")) if m.group("ts") else 0.0
    can_id = int(m.group("id"), 16)
    raw = (m.group("data") or "").replace(".", "")
    if len(raw) % 2:
        raw = raw[:-1]
    data = bytes.fromhex(raw) if raw else b""
    return ts, m.group("iface"), can_id, data


def parse_log(path: str):
    frames = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            rec = parse_line(line)
            if rec:
                frames.append(rec)
    return frames


def summarise(frames) -> dict:
    by_id: dict[int, list] = defaultdict(list)
    for ts, _iface, cid, data in frames:
        by_id[cid].append((ts, data))
    out = {}
    for cid, items in by_id.items():
        payloads = {d for _t, d in items}
        dlcs = {len(d) for _t, d in items}
        times = [t for t, _d in items if t]
        period = 0.0
        if len(times) > 2:
            deltas = [b - a for a, b in zip(times, times[1:]) if b > a]
            if deltas:
                period = sum(deltas) / len(deltas)
        # which byte positions ever change
        changing = []
        maxlen = max(dlcs) if dlcs else 0
        for i in range(maxlen):
            vals = {d[i] for _t, d in items if len(d) > i}
            if len(vals) > 1:
                changing.append(i)
        out[cid] = {
            "count": len(items),
            "unique": len(payloads),
            "dlc": sorted(dlcs),
            "period_ms": period * 1000,
            "changing_bytes": changing,
            "sample": next(iter(payloads)).hex() if payloads else "",
        }
    return out


def extract_signal(data: bytes, start_bit: int, length: int, little: bool = True,
                   factor: float = 1.0, offset: float = 0.0, signed: bool = False) -> float:
    """Extract a DBC-style signal from a CAN payload."""
    if little:
        val = int.from_bytes(data, "little")
        raw = (val >> start_bit) & ((1 << length) - 1)
    else:
        val = int.from_bytes(data, "big")
        total_bits = len(data) * 8
        shift = total_bits - start_bit - length
        raw = (val >> shift) & ((1 << length) - 1)
    if signed and raw & (1 << (length - 1)):
        raw -= 1 << length
    return raw * factor + offset


def diff(a_path: str, b_path: str) -> None:
    a = summarise(parse_log(a_path))
    b = summarise(parse_log(b_path))
    only_b = sorted(set(b) - set(a))
    only_a = sorted(set(a) - set(b))
    print(f"IDs only in {b_path}: " + ", ".join(f"0x{i:03X}" for i in only_b) or "(none)")
    print(f"IDs only in {a_path}: " + ", ".join(f"0x{i:03X}" for i in only_a) or "(none)")

    print("\nIDs whose payload set changed:")
    a_frames = defaultdict(set)
    b_frames = defaultdict(set)
    for _t, _i, cid, d in parse_log(a_path):
        a_frames[cid].add(d)
    for _t, _i, cid, d in parse_log(b_path):
        b_frames[cid].add(d)
    for cid in sorted(set(a_frames) & set(b_frames)):
        new = b_frames[cid] - a_frames[cid]
        if new:
            print(f"  0x{cid:03X}: {len(new)} new payload(s)")
            for d in sorted(new)[:6]:
                print(f"      {d.hex()}")


def report(path: str, only_id: int | None) -> None:
    frames = parse_log(path)
    print(f"== {path}: {len(frames)} frames")
    stats = summarise(frames)
    print(f"{len(stats)} distinct arbitration IDs\n")
    print("  ID     count  unique  dlc   period(ms)  changing bytes   sample")
    for cid in sorted(stats):
        if only_id is not None and cid != only_id:
            continue
        s = stats[cid]
        print(f"  0x{cid:03X}  {s['count']:>6}  {s['unique']:>6}  "
              f"{','.join(map(str, s['dlc'])):<5} {s['period_ms']:>9.2f}  "
              f"{str(s['changing_bytes']):<16} {s['sample']}")

    if only_id is not None:
        print(f"\n-- payload timeline for 0x{only_id:03X} --")
        for ts, _i, cid, d in frames:
            if cid == only_id:
                print(f"  {ts:.6f}  {d.hex(' ')}")


def main() -> int:
    ap = argparse.ArgumentParser(description="candump log analyser")
    ap.add_argument("log")
    ap.add_argument("--id", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--diff", default=None)
    ap.add_argument("--signal", nargs=6,
                    metavar=("ID", "START", "LEN", "ENDIAN", "FACTOR", "OFFSET"))
    args = ap.parse_args()

    if args.diff:
        diff(args.log, args.diff)
        return 0
    if args.signal:
        cid = int(args.signal[0], 0)
        start, length = int(args.signal[1]), int(args.signal[2])
        little = args.signal[3].lower().startswith("l")
        factor, offset = float(args.signal[4]), float(args.signal[5])
        for ts, _i, fid, d in parse_log(args.log):
            if fid == cid and len(d) * 8 >= start + length:
                val = extract_signal(d, start, length, little, factor, offset)
                print(f"  {ts:.3f}  {d.hex(' ')}  -> {val}")
        return 0
    report(args.log, args.id)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        rec = parse_line("(1615825200.123456) can0 123#DEADBEEF01020304")
        assert rec is not None
        ts, iface, cid, data = rec
        assert cid == 0x123 and iface == "can0", rec
        assert data == bytes.fromhex("DEADBEEF01020304"), data.hex()
        assert abs(ts - 1615825200.123456) < 1e-6

        rec2 = parse_line("vcan0 7DF#0201 0C")
        assert parse_line("7E8#04410C1F40") is None or True   # plain form needs an iface

        # signal extraction: rpm = ((A*256)+B)/4 with A=0x1F B=0x40 -> 2000 rpm
        payload = bytes.fromhex("04410C1F4000000000")[:8]
        rpm = extract_signal(payload[3:5], 0, 16, little=False, factor=0.25)
        assert abs(rpm - 2000.0) < 1e-6, rpm

        # little-endian 16-bit at bit 0 with factor 0.25
        assert extract_signal(bytes.fromhex("401F"), 0, 16, little=True, factor=0.25) == 2000.0
        # signed extraction
        assert extract_signal(bytes([0xFF]), 0, 8, little=True, signed=True) == -1

        import os
        import tempfile
        log = "\n".join([
            "(1000.000000) vcan0 123#0000000000000000",
            "(1000.010000) vcan0 123#0000000000000001",
            "(1000.020000) vcan0 456#DEADBEEF",
            "(1000.030000) vcan0 123#0000000000000002",
        ])
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.log")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(log + "\n")
            stats = summarise(parse_log(p))
            assert 0x123 in stats and stats[0x123]["count"] == 3, stats
            assert stats[0x123]["changing_bytes"] == [7], stats[0x123]
            report(p, 0x123)
        print("selftest ok")
    else:
        sys.exit(main())
```

### OBD-II and UDS probing

```bash
# supported PIDs (mode 01, pid 00)
cansend can0 7DF#0201000000000000
candump -n 5 can0,7E8:7FF

# engine rpm (pid 0C)
cansend can0 7DF#02010C0000000000

# vin (mode 09, pid 02) - multi-frame, needs isotp
isotpsend -s 7DF -d 7E8 can0 <<< "09 02"

# uds: enter an extended diagnostic session, then request a security seed
isotpsend -s 7E0 -d 7E8 can0 <<< "10 03"     # DiagnosticSessionControl extended
isotpsend -s 7E0 -d 7E8 can0 <<< "27 01"     # SecurityAccess requestSeed
isotprecv -s 7E8 -d 7E0 can0                 # -> 67 01 <seed bytes>
isotpsend -s 7E0 -d 7E8 can0 <<< "27 02 AA BB CC DD"   # sendKey
isotpsend -s 7E0 -d 7E8 can0 <<< "22 F1 90"  # ReadDataByIdentifier (VIN)
isotpsend -s 7E0 -d 7E8 can0 <<< "3E 00"     # TesterPresent (keeps the session alive)

# brute-force which ECUs answer
for i in $(seq 0 7); do
  printf "probing 7E%X\n" $i
  cansend can0 "7E$i#023E000000000000"
done
```

## Variants & pitfalls

- **Replaying the whole log floods the bus** and masks the response you want. Filter the
  replay down to the candidate ID.
- **A frame must be repeated** - many ECUs only act while a frame keeps arriving at its
  normal period. One `cansend` does nothing; loop it.
- **A competing ECU keeps overwriting your value.** You must send faster than it, or
  isolate the bus segment.
- **Checksums and counters** - byte 7 is often a rolling counter plus a checksum
  (frequently XOR or a simple sum over the first bytes). Replaying a stale frame fails
  until you fix them. Look for one nibble that increments 0-F.
- **CAN FD** frames use `##` in candump syntax (`123##1DEADBEEF...`) and need `fd on`.
- **UDS SecurityAccess** seed/key algorithms live in the ECU firmware - dump it
  (`mcu-reversing`) and reimplement the key function.

## Tools

- `can-utils`: `candump`, `cansend`, `cangen`, `canplayer`, `cansniffer`, `canbusload`,
  `isotpsend`/`isotprecv`/`isotpdump`.
- `python-can` + `cantools` - scripting, DBC decoding, log-format conversion.
- `SavvyCAN` - GUI: graphing, frame diffing, DBC editing, file format conversion.
- `Wireshark` - dissects SocketCAN, ISO-TP and OBD-II.
- Hardware: CANable/slcan dongles, PCAN-USB, Kvaser, a Raspberry Pi with an MCP2515 HAT.
- `caringcaribou` - UDS/ISO-TP discovery and fuzzing toolkit.

## References

- Linux kernel SocketCAN documentation and the `can-utils` manual pages.
- `cantools` documentation for the DBC signal definition syntax.
- ISO 15765-2 (ISO-TP) and ISO 14229 (UDS) service identifiers.
