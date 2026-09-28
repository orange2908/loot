---
title: "Scapy for Forensics - Read, Filter, Reassemble, Rewrite"
category: forensics
subcategory: network
type: technique
tags: [scapy, pcap, pcapng, rdpcap, pcapreader, wrpcap, tcp-reassembly, packet-crafting, checksum, defragment, sessions, python, network-forensics, dfir, pcap-rewriting]
difficulty: medium
summary: "Use scapy as a forensics tool: stream a capture without loading it, reassemble TCP the way you want, and rewrite packets with correct checksums."
when_to_use:
  - "tshark cannot express the filter or transformation you need"
  - "You must reassemble a stream that Wireshark's dissector gets wrong"
  - "The capture uses a custom protocol and you want to parse it in Python"
  - "You need to anonymise, split, merge or repair a pcap programmatically"
tools: [scapy, python3, tshark, editcap]
related: [network-pcap-triage, network-extract-files-creds, network-covert-channels, network-c2-analysis, network-usb-hid]
---

## TL;DR

`rdpcap()` loads the whole file into RAM -- use `PcapReader` as a context manager for anything
over a few hundred megabytes. Scapy's `sessions()` is a convenience, not a real reassembler;
write your own when sequence numbers matter. After editing any field, delete the checksums and
re-parse the bytes so scapy recomputes them.

## Recognise it

- You are about to write a bash loop with twenty `tshark` invocations. Write one scapy script.
- The dissector shows `[Malformed Packet]` but the bytes are fine.
- You need per-packet state (sequence tracking, a decoder, a running key).
- The link type is USB, Bluetooth or 802.11 and you want raw field access.

## Install and load

```sh
# scapy is pure python; no compiler needed for the parts used here
pip install scapy
# optional extras: cryptography for the TLS layer, matplotlib for plots
pip install scapy[basic] matplotlib cryptography
# interactive shell, great for exploring an unfamiliar capture
scapy
# one-liner mode
python3 -c "from scapy.all import *; print(rdpcap('cap.pcap')[:5])"
```

```python
from scapy.all import (rdpcap, PcapReader, PcapWriter, wrpcap, sniff, raw, hexdump,
                       Raw, ls, lsc, conf)
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse   # scapy >= 2.4.3
```

## Reading

```python
# loads everything into memory - fine for small captures, fatal for big ones
pkts = rdpcap("cap.pcap")
print(len(pkts), pkts[0].summary())

# streaming: constant memory, works on multi-gigabyte files
with PcapReader("cap.pcap") as pr:
    for pkt in pr:
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
            print(pkt.summary())

# BPF filtering while reading a FILE (yes, the capture filter works offline)
sniff(offline="cap.pcap", filter="tcp port 80 and host 10.0.0.5",
      prn=lambda p: p.summary(), store=False)

# stop after N matches
sniff(offline="cap.pcap", filter="icmp", count=10, prn=lambda p: p.show())

# a custom predicate instead of BPF
sniff(offline="cap.pcap", lfilter=lambda p: p.haslayer(Raw) and b"flag" in bytes(p[Raw].load),
      prn=lambda p: hexdump(p), store=False)
```

Inspection helpers:

```python
pkt.summary()          # one line
pkt.show()             # full field tree, as parsed
pkt.show2()            # same, but after rebuilding (recomputes lengths/checksums)
hexdump(pkt)           # hex + ascii of the whole frame
raw(pkt)               # bytes(pkt): the wire bytes
bytes(pkt[TCP].payload)
pkt.haslayer(TCP), pkt.getlayer(IP, 2)       # second IP layer, e.g. in ICMP errors
pkt.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport% %TCP.flags%")
pkt.time                                      # epoch float
pkt.layers()                                  # [Ether, IP, TCP, Raw]
ls(TCP)                                       # every field of a layer with its type
lsc()                                         # every scapy command
conf.l2types                                  # link-type number -> layer class
```

Iterating layers safely:

```python
layer = pkt
while layer:
    print(type(layer).__name__)
    layer = layer.payload if layer.payload else None
```

## Filtering and selecting

```python
# scapy PacketList supports filter/ slicing / sorting
tcp_only = pkts.filter(lambda p: p.haslayer(TCP))
big = pkts.filter(lambda p: len(p) > 1000)
first_ten = pkts[:10]

# quick visual summaries
pkts.nsummary()
pkts.conversations()           # needs graphviz; writes a graph
pkts.sessions()                # dict: "TCP 10.0.0.1:1234 > 10.0.0.2:80" -> PacketList

# custom session keys (normalise direction so both halves land together)
def flowkey(p):
    if p.haslayer(TCP) and p.haslayer(IP):
        a = (p[IP].src, p[TCP].sport)
        b = (p[IP].dst, p[TCP].dport)
        lo, hi = sorted([a, b])
        return f"TCP {lo[0]}:{lo[1]}<->{hi[0]}:{hi[1]}"
    return "other"

for key, plist in pkts.sessions(flowkey).items():
    print(key, len(plist))
```

`sessions()` groups packets; it does **not** order by sequence number, drop retransmissions, or
handle overlaps. For anything where the byte stream matters, use the reassembler below.

## Writing and rewriting

```python
# write a list of packets
wrpcap("out.pcap", pkts)

# streaming writer: append as you go, flush each packet (survives a crash)
w = PcapWriter("out.pcap", append=True, sync=True)
with PcapReader("in.pcap") as pr:
    for pkt in pr:
        if pkt.haslayer(IP):
            w.write(pkt)
w.close()

# preserve the original link type when writing a non-Ethernet capture
wrpcap("out.pcap", pkts, linktype=conf.l2types.layer2num.get(Ether, 1))
```

**The checksum rule.** After changing any field that a checksum covers, delete every checksum and
re-parse, or the packet will be written with the old (now wrong) value:

```python
pkt[IP].src = "192.0.2.10"
del pkt[IP].chksum
del pkt[IP].len
if pkt.haslayer(TCP):
    del pkt[TCP].chksum
elif pkt.haslayer(UDP):
    del pkt[UDP].chksum
    del pkt[UDP].len
pkt = pkt.__class__(bytes(pkt))      # rebuild -> scapy recomputes the deleted fields
```

Crafting from scratch:

```python
p = (Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
     IP(src="10.0.0.1", dst="10.0.0.2") /
     TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=1) /
     Raw(load=b"GET /flag HTTP/1.1\r\nHost: t\r\n\r\n"))
wrpcap("crafted.pcap", [p])
```

Fragmentation:

```python
from scapy.layers.inet import fragment, defragment, defrag
frags = fragment(IP(dst="10.0.0.2") / ICMP() / (b"A" * 4000), fragsize=1400)
whole = defragment(frags)            # returns the reassembled packets
nofrag, defragged, couldnt = defrag(frags)
```

## Link types other than Ethernet

```python
# scapy picks the layer from the pcap link type automatically
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.bluetooth import HCI_Hdr
# USB captures: scapy parses the usbmon pseudo-header on Linux link types
with PcapReader("usb.pcap") as pr:
    for pkt in pr:
        data = bytes(pkt)[64:]        # usbmon mmapped header is 64 bytes
        if data:
            print(data.hex())
# optional layers that must be loaded explicitly
from scapy.all import load_layer, load_contrib
load_layer("tls")         # TLS record parsing (needs cryptography)
load_contrib("http2")     # HTTP/2 frames
load_contrib("modbus")    # industrial protocols
```

## pcap vs pcapng

Scapy writes classic **pcap**. It can read pcapng but loses the per-block metadata (interface
descriptions, comments, Decryption Secrets Blocks). Round-trip through `editcap` when you need
pcapng out:

```sh
# scapy output -> pcapng
editcap -F pcapng out.pcap out.pcapng
# preserve nanosecond timestamps
editcap -F nsecpcap in.pcap out_ns.pcap
# scapy loses DSB secrets; re-inject them afterwards
editcap --inject-secrets tls,keys.log out.pcap out.pcapng
```

## Code

```python
#!/usr/bin/env python3
"""TCP stream reassembler: sequence-ordered, retransmit- and overlap-safe.

Writes <outdir>/stream_<n>_<src>_<sport>-<dst>_<dport>.bin per direction.

    pip install scapy
    python3 tcp_reassemble.py capture.pcap --outdir streams
    python3 tcp_reassemble.py --selftest
"""
from __future__ import annotations

import argparse
import os
import sys

FlowKey = tuple[str, int, str, int]


class Direction:
    """One half of a TCP conversation, reassembled by absolute sequence number."""

    def __init__(self) -> None:
        self.segments: dict[int, bytes] = {}
        self.isn: int | None = None
        self.syn_seen = False
        self.fin_seen = False
        self.retransmits = 0
        self.overlaps = 0

    def add(self, seq: int, data: bytes, syn: bool = False, fin: bool = False) -> None:
        if syn:
            self.syn_seen = True
            self.isn = seq
        if fin:
            self.fin_seen = True
        if not data:
            return
        prior = self.segments.get(seq)
        if prior is not None:
            if len(data) <= len(prior):
                self.retransmits += 1
                return
            self.retransmits += 1
        self.segments[seq] = data

    def assemble(self, fill: bytes = b"") -> tuple[bytes, int]:
        """Return (stream_bytes, missing_byte_count)."""
        if not self.segments:
            return b"", 0
        out = bytearray()
        expected: int | None = None
        missing = 0
        for seq in sorted(self.segments):
            data = self.segments[seq]
            if expected is None:
                expected = seq
            if seq < expected:
                skip = expected - seq
                if skip >= len(data):
                    self.overlaps += 1
                    continue
                self.overlaps += 1
                data = data[skip:]
                seq = expected
            elif seq > expected:
                gap = seq - expected
                missing += gap
                if fill:
                    out.extend(fill * gap)
            out.extend(data)
            expected = seq + len(data)
        return bytes(out), missing


def reassemble(pcap: str, bpf: str | None = None) -> dict[FlowKey, Direction]:
    try:
        from scapy.all import PcapReader, Raw  # type: ignore
        from scapy.layers.inet import IP, TCP  # type: ignore
        from scapy.layers.inet6 import IPv6  # type: ignore
    except ImportError:
        print("scapy is required:  pip install scapy", file=sys.stderr)
        raise SystemExit(1)

    flows: dict[FlowKey, Direction] = {}
    with PcapReader(pcap) as reader:
        for pkt in reader:
            if not pkt.haslayer(TCP):
                continue
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue
            tcp = pkt[TCP]
            key: FlowKey = (src, int(tcp.sport), dst, int(tcp.dport))
            direction = flows.setdefault(key, Direction())
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            flags = int(tcp.flags)
            direction.add(int(tcp.seq), payload,
                          syn=bool(flags & 0x02), fin=bool(flags & 0x01))
    return flows


def selftest() -> int:
    d = Direction()
    d.add(1000, b"", syn=True)
    d.add(1001, b"HELLO ")
    d.add(1007, b"WORLD")
    d.add(1001, b"HELLO ")          # exact retransmit
    data, missing = d.assemble()
    assert data == b"HELLO WORLD", data
    assert missing == 0 and d.retransmits == 1, (missing, d.retransmits)

    # overlapping segment: second copy starts inside the first
    o = Direction()
    o.add(0, b"ABCDEF")
    o.add(3, b"DEFGHI")
    data, missing = o.assemble()
    assert data == b"ABCDEFGHI", data
    assert o.overlaps == 1, o.overlaps

    # gap
    g = Direction()
    g.add(0, b"AAAA")
    g.add(10, b"BBBB")
    data, missing = g.assemble()
    assert data == b"AAAABBBB" and missing == 6, (data, missing)
    data, missing = Direction().assemble()
    assert data == b"" and missing == 0

    g2 = Direction()
    g2.add(0, b"AAAA")
    g2.add(6, b"BBBB")
    data, missing = g2.assemble(fill=b"\x00")
    assert data == b"AAAA\x00\x00BBBB", data
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--outdir", default="streams")
    ap.add_argument("--fill", action="store_true", help="pad gaps with NUL bytes")
    ap.add_argument("--min-size", type=int, default=1)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.pcap:
        return selftest()

    flows = reassemble(args.pcap)
    os.makedirs(args.outdir, exist_ok=True)
    print(f"{'bytes':>10} {'gaps':>7} {'rexmit':>7}  flow")
    written = 0
    for i, (key, direction) in enumerate(
            sorted(flows.items(), key=lambda kv: -sum(len(v) for v in kv[1].segments.values()))):
        data, missing = direction.assemble(b"\x00" if args.fill else b"")
        if len(data) < args.min_size:
            continue
        src, sport, dst, dport = key
        name = f"stream_{i:04d}_{src}_{sport}-{dst}_{dport}.bin".replace(":", "_")
        with open(os.path.join(args.outdir, name), "wb") as fh:
            fh.write(data)
        written += 1
        print(f"{len(data):>10} {missing:>7} {direction.retransmits:>7}  "
              f"{src}:{sport} -> {dst}:{dport}")
    print(f"\n[+] {written} directions written to {args.outdir}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Rewrite a pcap: remap IPs and ports, recompute checksums, write a new file.

Useful for anonymising a capture before sharing, for normalising an exercise, or
for repairing a capture whose checksums were broken by an offloading NIC.

    pip install scapy
    python3 pcap_rewrite.py in.pcap out.pcap --map-ip 10.0.0.5=192.0.2.5 \\
        --map-port 4444=8080 --anonymise
    python3 pcap_rewrite.py --selftest
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import sys


def load_scapy():
    try:
        from scapy.all import PcapReader, PcapWriter, Raw, raw, wrpcap  # type: ignore
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
        return {"PcapReader": PcapReader, "PcapWriter": PcapWriter, "Raw": Raw,
                "raw": raw, "wrpcap": wrpcap, "IP": IP, "TCP": TCP, "UDP": UDP,
                "Ether": Ether}
    except ImportError:
        print("scapy is required:  pip install scapy", file=sys.stderr)
        raise SystemExit(1)


def pseudonymise(addr: str, prefix: str = "198.51.100") -> str:
    """Deterministic, reversible-per-run mapping into a documentation range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return addr
    if ip.version != 4:
        return addr
    digest = hashlib.sha256(addr.encode()).digest()
    return f"{prefix}.{1 + digest[0] % 254}"


def rewrite_packet(pkt, ip_map: dict[str, str], port_map: dict[int, int],
                   anonymise: bool, mods, strip_payload: bool):
    IP, TCP, UDP, Raw = mods["IP"], mods["TCP"], mods["UDP"], mods["Raw"]
    changed = False
    if pkt.haslayer(IP):
        ip = pkt[IP]
        for attr in ("src", "dst"):
            cur = getattr(ip, attr)
            new = ip_map.get(cur)
            if new is None and anonymise and not ipaddress.ip_address(cur).is_private:
                new = pseudonymise(cur)
            if new and new != cur:
                setattr(ip, attr, new)
                changed = True
        if changed:
            for field in ("chksum", "len"):
                if hasattr(ip, field):
                    delattr(ip, field)

    for layer_cls in (TCP, UDP):
        if pkt.haslayer(layer_cls):
            layer = pkt[layer_cls]
            for attr in ("sport", "dport"):
                cur = int(getattr(layer, attr))
                new = port_map.get(cur)
                if new and new != cur:
                    setattr(layer, attr, new)
                    changed = True
            if changed:
                if hasattr(layer, "chksum"):
                    del layer.chksum
                if layer_cls is UDP and hasattr(layer, "len"):
                    del layer.len

    if strip_payload and pkt.haslayer(Raw):
        pkt[Raw].load = b"\x00" * len(pkt[Raw].load)
        changed = True

    if not changed:
        return pkt
    return pkt.__class__(bytes(pkt))      # rebuild so deleted fields are recomputed


def parse_map(pairs: list[str], cast=str) -> dict:
    out = {}
    for item in pairs or []:
        if "=" not in item:
            raise SystemExit(f"bad mapping {item!r}, expected OLD=NEW")
        old, new = item.split("=", 1)
        out[cast(old)] = cast(new)
    return out


def selftest() -> int:
    mods = load_scapy()
    IP, TCP, Raw = mods["IP"], mods["TCP"], mods["Raw"]
    pkt = IP(src="203.0.113.7", dst="10.0.0.5") / TCP(sport=4444, dport=80) / Raw(load=b"hello")
    original = bytes(pkt)
    out = rewrite_packet(pkt.copy(), {"203.0.113.7": "192.0.2.1"}, {4444: 8080},
                         False, mods, False)
    assert out[IP].src == "192.0.2.1", out[IP].src
    assert int(out[TCP].sport) == 8080, out[TCP].sport
    assert out[IP].chksum is not None and out[IP].chksum != 0
    assert bytes(out) != original
    # checksum must actually be correct: rebuilding again must not change it
    again = out.__class__(bytes(out))
    assert again[IP].chksum == out[IP].chksum

    # note: python's ipaddress marks the documentation ranges (192.0.2.0/24,
    # 198.51.100.0/24, 203.0.113.0/24) as private, so use a genuinely public one here
    anon = rewrite_packet(IP(src="8.8.8.8", dst="1.1.1.1") / TCP(), {}, {}, True, mods, False)
    assert anon[IP].src.startswith("198.51.100."), anon[IP].src
    assert pseudonymise("8.8.8.8") == pseudonymise("8.8.8.8")

    priv = rewrite_packet(IP(src="10.1.2.3", dst="10.1.2.4") / TCP(), {}, {}, True, mods, False)
    assert priv[IP].src == "10.1.2.3", "private addresses must be left alone"
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("infile", nargs="?")
    ap.add_argument("outfile", nargs="?")
    ap.add_argument("--map-ip", action="append", metavar="OLD=NEW")
    ap.add_argument("--map-port", action="append", metavar="OLD=NEW")
    ap.add_argument("--anonymise", action="store_true",
                    help="pseudonymise every public IPv4 address")
    ap.add_argument("--strip-payload", action="store_true",
                    help="zero every Raw payload (keep headers only)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not (args.infile and args.outfile):
        return selftest()

    mods = load_scapy()
    ip_map = parse_map(args.map_ip or [])
    port_map = parse_map(args.map_port or [], int)

    writer = mods["PcapWriter"](args.outfile, append=False, sync=False)
    count = 0
    with mods["PcapReader"](args.infile) as reader:
        for pkt in reader:
            new = rewrite_packet(pkt, ip_map, port_map, args.anonymise, mods,
                                 args.strip_payload)
            new.time = pkt.time
            writer.write(new)
            count += 1
    writer.close()
    print(f"[+] {count} packets written to {args.outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **`rdpcap` on a 4 GB capture will use far more than 4 GB** because every packet becomes a Python
  object tree. Always `PcapReader` for big files.
- **Sequence numbers wrap** at 2^32. A long-lived stream will produce a bogus ordering unless you
  track the wrap. For CTF-sized captures this almost never bites; for real captures it does.
- Scapy's `sessions()` uses the **string** key by default, which separates the two directions of
  the same conversation. Pass your own key function if you want them together.
- `pkt.time` is a `Decimal`/`EDecimal` in recent scapy. `float(pkt.time)` before arithmetic.
- `del pkt[IP].chksum` alone is not enough -- you must **rebuild** (`pkt.__class__(bytes(pkt))`)
  or write through `PcapWriter`, which serialises and recomputes.
- **Bad checksums in a capture are usually normal**: NIC offloading computes them after capture.
  Do not treat them as tampering evidence without corroboration.
- `Raw` only appears when scapy has no dissector. If a protocol is dissected, the bytes are in the
  typed layer, not `Raw`; use `bytes(pkt[TCP].payload)` to be safe.
- Writing a non-Ethernet capture without setting `linktype` produces a file every tool
  misinterprets.
- Scapy can **send** packets. Never let a forensics script do that by accident -- avoid `sr`,
  `sr1`, `send`, `sendp` entirely in an analysis script.

## Tools

`scapy`, `python3`, `tshark`/`editcap` for format conversion, `dpkt` (faster, lower level),
`pyshark` (a tshark wrapper if you want Wireshark's dissectors from Python),
`nfstream`/`pypacker` as alternatives.

## References

- `lsc()` inside the scapy shell lists every command; `ls(Layer)` lists a layer's fields.
- `explore()` in the scapy shell browses all available protocol layers and contribs.
