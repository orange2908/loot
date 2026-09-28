---
title: "ICS and OT Protocols - Modbus, S7comm and DNP3"
category: hardware
subcategory: ics
type: technique
tags: [modbus, modbus-tcp, s7comm, dnp3, plc, scada, ics, ot, pymodbus, snap7, nmap-scripts, wireshark, tshark, coils, holding-registers, function-codes, siemens]
difficulty: medium
summary: "Parse an ICS capture and talk to a simulated PLC: Modbus coils and registers, S7comm data blocks, DNP3 objects."
when_to_use:
  - "The challenge gives you a pcap with port 502, 102 or 20000 traffic"
  - "There is a simulated PLC you must read values from or write to"
  - "The flag is in a holding register, a data block, or a DNP3 point"
tools: [pymodbus, snap7, nmap, wireshark, tshark, modbus-cli, python]
related: [can-bus-automotive, logic-analyzer-decoding, firmware-emulation, uart-serial]
---

## TL;DR

Modbus (TCP/502) has no authentication: read coils (FC1), discrete inputs (FC2),
holding registers (FC3) and input registers (FC4); write with FC5/FC6/FC15/FC16.
S7comm (TCP/102) needs a COTP+S7 session but `python-snap7` does it in three lines.
DNP3 (TCP/20000) is more structured but the same idea. In a pcap, filter
`modbus`, `s7comm` or `dnp3` in Wireshark and read the register values directly.

## Recognise it

- pcap with TCP port **502** (Modbus), **102** (S7comm / ISO-TSAP), **20000** (DNP3),
  **44818/2222** (EtherNet/IP + CIP), **47808** (BACnet/UDP), **789** (Red Lion),
  **1911/4911** (Niagara Fox).
- Wireshark dissects them automatically: protocol column shows `Modbus/TCP`, `S7COMM`,
  `DNP 3.0`.
- Challenge text mentioning a PLC, HMI, SCADA, RTU, ladder logic, setpoints, tank levels.
- `nmap -p 502 --script modbus-discover` returns slave ids.

## Theory

### Modbus

A Modbus TCP frame is a 7-byte MBAP header plus the PDU:

```
 0-1  transaction id
 2-3  protocol id (0x0000)
 4-5  length (bytes following, including unit id)
 6    unit id (slave address)
 7    function code
 8..  data
```

Four separate address spaces, each 0-65535, each addressed from 0 in the protocol
(but often documented 1-based, with a 4xxxx/3xxxx/1xxxx/0xxxx prefix):

| Space | Read FC | Write FC | Size | Conventional numbering |
|---|---|---|---|---|
| Coils (RW bits) | 1 | 5 (single), 15 (multiple) | 1 bit | 0xxxx |
| Discrete inputs (RO bits) | 2 | - | 1 bit | 1xxxx |
| Input registers (RO words) | 4 | - | 16 bit | 3xxxx |
| Holding registers (RW words) | 3 | 6 (single), 16 (multiple) | 16 bit | 4xxxx |

Other useful function codes: 7 (read exception status), 8 (diagnostics),
17/0x11 (report slave id - a fingerprint), 20/21 (read/write file record),
43/0x2B (read device identification: vendor, product, version).

Registers are big-endian 16-bit. A 32-bit value spans two registers, and vendors
disagree on word order - try both. ASCII strings are packed two characters per register.

**There is no authentication and no encryption.** Anything reachable is writable.

### S7comm (Siemens S7-300/400/1200/1500)

Runs over ISO-TSAP (RFC1006) on port 102. A connection needs a **rack** and **slot**
(commonly 0/2 for S7-300/400, 0/1 for S7-1200/1500). Memory areas:

| Area | Name | snap7 constant |
|---|---|---|
| DB | data blocks | `Areas.DB` |
| M | merkers / flags | `Areas.MK` |
| I / E | process inputs | `Areas.PE` |
| Q / A | process outputs | `Areas.PA` |
| T | timers | `Areas.TM` |
| C | counters | `Areas.CT` |

S7-1200/1500 add "optimised block access" and optional password protection; legacy
S7comm reads fail against those unless optimisation is off.

### DNP3

Three layers: data link (start bytes `0x05 0x64`, CRC every 16 bytes), transport, and
application. Objects are addressed by **group** and **variation**:
group 1 = binary input, 10 = binary output, 30 = analog input, 40 = analog output,
20 = counters, 50 = time. Function codes: 1 read, 2 write, 3 select, 4 operate,
5 direct operate, 13 cold restart.

The link layer has 16-bit source and destination addresses; unsolicited responses are
common. Secure Authentication (SAv5) exists but is rarely enabled.

## Attack

1. In a pcap: filter by protocol, look at the register/point values over time.
2. Live target: `nmap` ICS scripts to fingerprint, then read everything.
3. Enumerate the full address space (coils 0-2000, holding registers 0-125 per request).
4. Look for ASCII in register values - flags are routinely stored two chars per register.
5. Write to the coil/register the challenge wants (open a valve, set a setpoint).
6. For S7, read DB1..DB20 and dump their bytes.

## Code

### Reading an ICS pcap

```bash
# what protocols are present
tshark -r plant.pcap -q -z io,phs | head -30
tshark -r plant.pcap -q -z conv,tcp | head -20

# --- modbus ---
tshark -r plant.pcap -Y 'modbus' | head -40
tshark -r plant.pcap -Y 'modbus' -T fields \
  -e frame.number -e ip.src -e ip.dst -e modbus.func_code \
  -e modbus.reference_num -e modbus.word_cnt -e modbus.regval_uint16
# just the register values that were read back
tshark -r plant.pcap -Y 'modbus.func_code == 3 && mbtcp.modbus.pdu' \
  -T fields -e modbus.regval_uint16 | tr '\n' ' '
# write operations: what did the HMI change?
tshark -r plant.pcap -Y 'modbus.func_code == 6 || modbus.func_code == 16' \
  -T fields -e modbus.reference_num -e modbus.regval_uint16

# --- s7comm ---
tshark -r plant.pcap -Y 's7comm' -T fields \
  -e s7comm.header.rosctr -e s7comm.param.func \
  -e s7comm.param.item.db -e s7comm.param.item.area -e s7comm.data.blockdata | head -30

# --- dnp3 ---
tshark -r plant.pcap -Y 'dnp3' -T fields \
  -e dnp3.al.func -e dnp3.al.obj -e dnp3.al.objq.index -e dnp3.al.ana | head -30

# --- raw payload extraction, protocol-agnostic ---
tshark -r plant.pcap -Y 'tcp.port==502 && tcp.len>0' -T fields -e data.data |
  tr -d '\n:' | xxd -r -p | strings -n 4 | sort -u | head -20
```

### Live enumeration with nmap

```bash
nmap -Pn -sT -p 102,502,20000,44818,47808,1911,4911,2404 10.0.0.10
nmap -Pn -p 502 --script modbus-discover --script-args='modbus-discover.aggressive=true' 10.0.0.10
nmap -Pn -p 102 --script s7-info 10.0.0.10
nmap -Pn -p 44818 --script enip-info 10.0.0.10
nmap -Pn -sU -p 47808 --script bacnet-info 10.0.0.10
nmap -Pn -p 20000 --script dnp3-info 10.0.0.10 2>/dev/null || true

# plcscan (older but thorough)
python2 plcscan.py 10.0.0.10

# modbus-cli (ruby gem) - quick one-liners
modbus read 10.0.0.10 %MW0 20
modbus write 10.0.0.10 %MW10 1234
```

### Modbus client

```python
#!/usr/bin/env python3
"""modbus_client.py - read/write a Modbus TCP device and hunt for ASCII in registers.

Uses pymodbus when available; the register decoding helpers are pure stdlib so the
parsing logic can be tested offline.

Usage:
  python3 modbus_client.py 10.0.0.10 --dump
  python3 modbus_client.py 10.0.0.10 --read-holding 0 50
  python3 modbus_client.py 10.0.0.10 --write-coil 3 1
  python3 modbus_client.py 10.0.0.10 --write-register 40 1337
"""
from __future__ import annotations

import argparse
import sys


def regs_to_ascii(regs: list[int], big_endian: bool = True) -> str:
    out = bytearray()
    for r in regs:
        hi, lo = (r >> 8) & 0xFF, r & 0xFF
        out.extend((hi, lo) if big_endian else (lo, hi))
    return "".join(chr(b) if 32 <= b < 127 else "." for b in out)


def regs_to_u32(regs: list[int], word_swap: bool = False) -> list[int]:
    out = []
    for i in range(0, len(regs) - 1, 2):
        a, b = regs[i], regs[i + 1]
        if word_swap:
            a, b = b, a
        out.append((a << 16) | b)
    return out


def regs_to_float(regs: list[int], word_swap: bool = False) -> list[float]:
    import struct

    out = []
    for v in regs_to_u32(regs, word_swap):
        out.append(struct.unpack(">f", v.to_bytes(4, "big"))[0])
    return out


def find_ascii(regs: list[int], min_len: int = 4) -> list[tuple[int, str]]:
    """Locate printable runs, reporting the starting register index."""
    hits = []
    text = regs_to_ascii(regs)
    run_start = None
    for i, ch in enumerate(text):
        if ch != ".":
            if run_start is None:
                run_start = i
        else:
            if run_start is not None and i - run_start >= min_len:
                hits.append((run_start // 2, text[run_start:i]))
            run_start = None
    if run_start is not None and len(text) - run_start >= min_len:
        hits.append((run_start // 2, text[run_start:]))
    return hits


def connect(host: str, port: int, unit: int):
    from pymodbus.client import ModbusTcpClient  # type: ignore

    client = ModbusTcpClient(host, port=port, timeout=5)
    if not client.connect():
        raise SystemExit(f"cannot connect to {host}:{port}")
    return client


def call(client, method: str, address: int, count: int, unit: int):
    """pymodbus changed the slave/unit kwarg between versions; try both."""
    fn = getattr(client, method)
    for kwargs in ({"slave": unit}, {"unit": unit}, {}):
        try:
            return fn(address, count, **kwargs)
        except TypeError:
            continue
    raise SystemExit(f"could not call {method}")


def dump(client, unit: int) -> None:
    print("== holding registers (FC3) ==")
    all_regs: list[int] = []
    for base in range(0, 500, 100):
        rr = call(client, "read_holding_registers", base, 100, unit)
        if rr.isError():
            print(f"  {base}-{base+99}: {rr}")
            continue
        all_regs.extend(rr.registers)
        for i, v in enumerate(rr.registers):
            if v:
                print(f"  hr[{base+i:>5}] = {v:>6} (0x{v:04x})")
    for idx, text in find_ascii(all_regs):
        print(f"  ASCII at holding register {idx}: {text!r}")

    print("\n== input registers (FC4) ==")
    rr = call(client, "read_input_registers", 0, 100, unit)
    if not rr.isError():
        for i, v in enumerate(rr.registers):
            if v:
                print(f"  ir[{i:>5}] = {v:>6} (0x{v:04x})")

    print("\n== coils (FC1) ==")
    rr = call(client, "read_coils", 0, 200, unit)
    if not rr.isError():
        on = [i for i, b in enumerate(rr.bits) if b]
        print(f"  coils set: {on}")

    print("\n== discrete inputs (FC2) ==")
    rr = call(client, "read_discrete_inputs", 0, 200, unit)
    if not rr.isError():
        on = [i for i, b in enumerate(rr.bits) if b]
        print(f"  inputs set: {on}")


def main() -> int:
    ap = argparse.ArgumentParser(description="modbus tcp client")
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--unit", type=int, default=1)
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--read-holding", nargs=2, type=int, metavar=("ADDR", "COUNT"))
    ap.add_argument("--read-coils", nargs=2, type=int, metavar=("ADDR", "COUNT"))
    ap.add_argument("--write-register", nargs=2, type=int, metavar=("ADDR", "VALUE"))
    ap.add_argument("--write-coil", nargs=2, type=int, metavar=("ADDR", "VALUE"))
    args = ap.parse_args()

    client = connect(args.host, args.port, args.unit)
    try:
        if args.dump:
            dump(client, args.unit)
        if args.read_holding:
            a, c = args.read_holding
            rr = call(client, "read_holding_registers", a, c, args.unit)
            print(rr.registers)
            print("ascii:", regs_to_ascii(rr.registers))
            print("u32  :", regs_to_u32(rr.registers))
        if args.read_coils:
            a, c = args.read_coils
            rr = call(client, "read_coils", a, c, args.unit)
            print(rr.bits)
        if args.write_register:
            a, v = args.write_register
            print(client.write_register(a, v, slave=args.unit))
        if args.write_coil:
            a, v = args.write_coil
            print(client.write_coil(a, bool(v), slave=args.unit))
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        text = "flag{modbus_regs}"
        padded = text + ("\x00" if len(text) % 2 else "")
        regs = [(ord(padded[i]) << 8) | ord(padded[i + 1])
                for i in range(0, len(padded), 2)]
        assert regs_to_ascii(regs).startswith("flag{modbus_regs}"), regs_to_ascii(regs)
        hits = find_ascii([0, 0] + regs + [0, 0])
        assert hits and "flag{modbus_regs}" in hits[0][1], hits
        assert hits[0][0] == 2, hits
        assert regs_to_u32([0x0001, 0x0002]) == [0x00010002]
        assert regs_to_u32([0x0001, 0x0002], word_swap=True) == [0x00020001]
        assert abs(regs_to_float([0x4048, 0xF5C3])[0] - 3.14) < 1e-5
        print("ascii:", regs_to_ascii(regs))
        print("hits :", hits)
        print("selftest ok")
    else:
        sys.exit(main())
```

### S7comm with snap7

```python
#!/usr/bin/env python3
"""s7_client.py - read Siemens S7 data blocks and scan DB1..DBn for readable content.

Requires python-snap7 and the snap7 shared library.
Rack/slot: 0/2 for S7-300/400, 0/1 for S7-1200/1500.

Usage:
  python3 s7_client.py 10.0.0.20                 # scan DB1..DB20
  python3 s7_client.py 10.0.0.20 5 0 64          # read DB5 bytes 0..63
"""
from __future__ import annotations

import sys


def printable(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    return "\n".join(
        f"  {base+off:04x}  {data[off:off+width].hex(' '):<{width*3}}"
        f"  |{printable(data[off:off+width])}|"
        for off in range(0, len(data), width))


def main(argv: list[str]) -> int:
    import snap7  # type: ignore

    host = argv[1]
    rack, slot = 0, 2
    client = snap7.client.Client()
    client.connect(host, rack, slot)
    print(f"connected to {host} rack={rack} slot={slot}: {client.get_connected()}")
    try:
        print("cpu info :", client.get_cpu_info())
        print("cpu state:", client.get_cpu_state())
    except Exception as exc:                      # noqa: BLE001 - snap7 raises broadly
        print("info failed:", exc)

    if len(argv) >= 5:
        db, start, size = int(argv[2]), int(argv[3]), int(argv[4])
        data = bytes(client.db_read(db, start, size))
        print(f"DB{db}[{start}:{start+size}]")
        print(hexdump(data, start))
    else:
        for db in range(1, 21):
            try:
                data = bytes(client.db_read(db, 0, 64))
            except Exception:                     # noqa: BLE001
                continue
            if any(data):
                print(f"\n== DB{db} (first 64 bytes) ==")
                print(hexdump(data))
    client.disconnect()
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv))
```

## Variants & pitfalls

- **Off-by-one addressing**: documentation uses 40001 for holding register 0.
  If a value looks shifted, adjust by one.
- **Unit/slave id** - a Modbus TCP gateway fronting serial devices needs the right unit
  id; try 0, 1, 255 and enumerate 1-247.
- **Word order for 32-bit values** - big-endian words (ABCD) vs swapped (CDAB). Try both;
  a float that reads as an absurd magnitude is the giveaway.
- **S7-1200/1500 refuse reads** unless "optimised block access" is disabled on the DB,
  or the connection uses the right rack/slot (0/1). Legacy S7comm vs S7comm-plus matters.
- **Flags hidden across registers**: read a large contiguous block and reassemble, rather
  than reading 10 registers at a time.
- **Serial Modbus RTU** in a challenge means a `.sr`/`.pcap` of a UART line: decode UART
  first (see `logic-analyzer-decoding`), then parse the RTU framing (address, function,
  data, CRC16-Modbus).

## Tools

- `pymodbus` (client, server and simulator), `modbus-cli`, `mbtget`, `QModMaster`.
- `python-snap7` + the snap7 library for S7.
- `nmap` NSE: `modbus-discover`, `s7-info`, `enip-info`, `bacnet-info`, `dnp3-info`.
- `wireshark` / `tshark` - excellent built-in dissectors for all three protocols.
- `plcscan`, `conpot` (honeypot, useful as a practice target).
- `scapy` contrib layers: `scapy.contrib.modbus`, `scapy.contrib.dnp3`.

## References

- Modbus Application Protocol Specification (function codes and the MBAP header).
- Wireshark dissector documentation for Modbus, S7COMM and DNP3 field names.
- python-snap7 documentation for area constants and client methods.
