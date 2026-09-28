---
title: "Tool - Scapy"
category: forensics
subcategory: packet-manipulation
type: tool
tags: [scapy, packets, pcap, rdpcap, sniff, sendp, craft, python, network, protocol, dissect, layers, forensics, custom-protocol, wireshark]
summary: "Python packet crafting and dissection: read a pcap into objects you can filter and reassemble, or build arbitrary packets and send them."
related: [wireshark-tshark, forensics-triage, remote-service]
---

## What it is

Scapy is a Python library that represents packets as layered objects. For CTF forensics it is what you reach for when `tshark` cannot express what you need: reassembling a custom protocol, extracting a field from thousands of packets, decoding covert-channel data, or scripting a stateful interaction. It also crafts and sends packets, which matters for network challenges and hardware/protocol work.

## Install

```sh
pipx install scapy          # provides the `scapy` REPL
python3 -m pip install scapy
# Debian/Kali
sudo apt install python3-scapy
# verify
python3 -c "import scapy.all as s; print(s.conf.version)"
```
Sending packets requires root (raw sockets). Reading a pcap does not.

## The invocations that matter

```python
#!/usr/bin/env python3
"""Scapy patterns for CTF pcap analysis."""
from scapy.all import (rdpcap, PcapReader, wrpcap, sniff, send, sendp, sr1, srp,
                       IP, IPv6, TCP, UDP, ICMP, Ether, ARP, DNS, DNSQR, DNSRR,
                       Raw, hexdump, ls, conf)
import collections

# 1. load a capture (rdpcap loads it all; PcapReader streams it)
pkts = rdpcap("capture.pcap")
print(len(pkts))
for p in PcapReader("big.pcap"):          # memory-safe for large files
    pass

# 2. inspect one packet
p = pkts[0]
p.show()                                   # full layered breakdown
p.summary()
hexdump(p)
print(p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport)

# 3. filter
http = [p for p in pkts if p.haslayer(TCP) and p[TCP].dport == 80]
withdata = [p for p in pkts if p.haslayer(Raw)]
dns_q = [p for p in pkts if p.haslayer(DNSQR)]
icmp = [p for p in pkts if p.haslayer(ICMP) and p.haslayer(Raw)]

# 4. reassemble one TCP stream in order
def stream(pkts, sport=None, dport=None):
    segs = {}
    for p in pkts:
        if not (p.haslayer(TCP) and p.haslayer(Raw)):
            continue
        if dport and p[TCP].dport != dport:
            continue
        if sport and p[TCP].sport != sport:
            continue
        segs[p[TCP].seq] = bytes(p[Raw].load)
    return b"".join(segs[k] for k in sorted(segs))

# 5. extract DNS exfiltration
labels = []
for p in pkts:
    if p.haslayer(DNSQR):
        name = p[DNSQR].qname.decode(errors="ignore")
        labels.append(name.split(".")[0])
print("".join(dict.fromkeys(labels)))       # dedupe preserving order

# 6. ICMP covert channel payloads
data = b"".join(bytes(p[Raw].load) for p in pkts
                if p.haslayer(ICMP) and p.haslayer(Raw))
print(data[:400])

# 7. statistics
c = collections.Counter((p[IP].src, p[IP].dst) for p in pkts if p.haslayer(IP))
for k, v in c.most_common(10):
    print(v, k)

# 8. craft and send (needs root)
send(IP(dst="10.0.0.1") / ICMP() / b"payload")
sendp(Ether() / IP(dst="10.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="a.ctf")))
ans = sr1(IP(dst="10.0.0.1") / TCP(dport=80, flags="S"), timeout=2)
if ans:
    ans.show()

# 9. live capture with a BPF filter and a callback
sniff(filter="tcp port 1337", prn=lambda x: x.summary(), count=20, iface="eth0")
sniff(offline="capture.pcap", filter="udp", prn=lambda p: print(p.summary()))

# 10. write results back out
wrpcap("filtered.pcap", withdata)
```

Defining a custom protocol (for a challenge with its own framing):
```python
from scapy.all import Packet, ByteField, ShortField, StrLenField, bind_layers, UDP

class CtfProto(Packet):
    name = "CtfProto"
    fields_desc = [
        ByteField("version", 1),
        ByteField("msg_type", 0),
        ShortField("length", 0),
        StrLenField("payload", b"", length_from=lambda p: p.length),
    ]

bind_layers(UDP, CtfProto, dport=1337)

pkts = rdpcap("capture.pcap")
for p in pkts:
    if p.haslayer(CtfProto):
        print(p[CtfProto].msg_type, p[CtfProto].payload)
```

USB HID keystroke extraction (a recurring CTF task):
```python
from scapy.all import rdpcap
# Scapy's USB support is limited; for USB pcaps prefer
#   tshark -r usb.pcap -T fields -e usb.capdata
# and decode the HID codes. See `ctfbrain search forensics-triage`.
```

## Gotchas

- `rdpcap` loads the **entire** capture into memory. A 1 GB pcap will exhaust RAM; use `PcapReader` as an iterator instead.
- Scapy is slow - roughly thousands of packets per second, not millions. For a first pass over a big capture, filter with `tshark`/`tcpdump` and then load the subset into Scapy.
- `p[Raw].load` exists only when there is payload; always check `p.haslayer(Raw)`.
- TCP reassembly is **not** automatic. Sort by `seq`, handle retransmissions (duplicate seq) and out-of-order delivery yourself, or use `tshark -z follow`.
- Sending requires root and a real interface. Inside a container without `NET_RAW` it will fail.
- Scapy's own layer 2 handling on loopback and on macOS differs; `conf.L3socket` may need adjusting.
- Importing `scapy.all` is slow (a second or two) and pulls in everything; that is normal.
- `sniff(filter=...)` uses BPF (capture-filter syntax), not Wireshark display-filter syntax.
- For pcapng files with multiple interfaces or comments, Scapy may lose metadata; convert with `editcap -F pcap` if something looks missing.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Standard protocol analysis | `tshark` - faster and already knows the protocol (`ctfbrain search wireshark-tshark`) |
| Large captures | `tcpdump -r in.pcap -w out.pcap '<bpf>'` first |
| File extraction | `tshark --export-objects`, `foremost -i f.pcap`, `networkminer` |
| Stream reassembly | `tshark -q -z follow,tcp,raw,N`, or Wireshark's Follow Stream |
| Summarised logs | `zeek -r f.pcap` |
| Fast packet generation | `hping3`, `nping`, `packETH` |
| Pure Python without Scapy | `dpkt` (lighter, faster, lower-level), or `python-libpcap` |
