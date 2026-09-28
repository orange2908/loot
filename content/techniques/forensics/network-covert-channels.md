---
title: "Covert Channels - DNS Exfiltration, ICMP Tunnelling and Protocol Abuse"
category: forensics
subcategory: network
type: technique
tags: [dns-exfiltration, dns-tunnelling, iodine, dnscat2, dnsteal, icmp-tunnel, ptunnel, icmpsh, covert-channel, steganography, base32, tshark, zeek, scapy, pcap, entropy, dfir]
difficulty: medium
summary: "Recognise data hidden in DNS labels, ICMP payloads, header fields and packet timing, then reassemble and decode it."
when_to_use:
  - "The protocol hierarchy shows a huge DNS or ICMP frame count relative to bytes"
  - "One domain accounts for thousands of unique long random subdomains"
  - "ICMP echo requests carry kilobytes and get no replies"
  - "Nothing obvious is in the payloads but the flag must have left the network somehow"
tools: [tshark, wireshark, zeek, scapy, python3, base64, xxd, ngrep]
related: [network-pcap-triage, network-c2-analysis, network-extract-files-creds, network-scapy-analysis]
---

## TL;DR

Covert channels hide data in fields that are supposed to be metadata. In DNS that is the QNAME
labels (usually base32, because DNS is case-insensitive); in ICMP it is the echo payload; in TCP
it is the ISN, urgent pointer or timestamp low bits. Find the anomalous field, concatenate the
values **in packet order**, then try base32 / base64 / hex / raw.

## Recognise it

- `-z io,phs` shows `dns` with a huge frame count but a small average size.
- One second-level domain dominates `dns.qry.name` and every query under it is unique.
- Subdomain labels are 30-63 characters of `[a-z0-9]` with no dictionary words.
- High NXDOMAIN rate (`dns.flags.rcode == 3`) or every response is a TXT/NULL/CNAME record.
- ICMP echo requests with a payload much larger than the usual 32/48/56 bytes, or with a payload
  that is not the standard incrementing byte pattern.
- Traffic to port 443 whose first bytes are not `16 03 01` (TLS handshake).
- A perfectly regular inter-packet interval (a timing channel or a beacon).

## DNS exfiltration

### What the tools look like

| Tool | Shape |
| --- | --- |
| `iodine` | NULL/TXT/CNAME/A records, encoded with base32/base64/base128, hostname prefix is a single-char topic code. Handshake with `vz`/`vt` style labels. |
| `dnscat2` | Usually TXT or CNAME; each query is hex, prefixed with a 16-bit session id. Often has a `dnscat.` prefix label. |
| `dns2tcp` | Base64 in the QNAME, TXT answers back. |
| `dnsteal` | Files split into labels, filename sent first; very chatty, one query per chunk. |
| Hand-rolled | base32/base64/hex labels, sometimes with a sequence-number label. |

### Extraction

```sh
# all queries (requests only), deduplicated
tshark -r cap.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u
# which parent domain dominates? strip to the last two labels and count
tshark -r cap.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name \
  | rev | cut -d. -f1,2 | rev | sort | uniq -c | sort -rn | head
# how many DISTINCT subdomains per parent (the real exfil signal)
tshark -r cap.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name \
  | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head
# query types in use: 16 = TXT, 10 = NULL, 5 = CNAME, 1 = A, 28 = AAAA
tshark -r cap.pcap -Y dns -T fields -e dns.qry.type | sort | uniq -c
# NXDOMAIN rate
tshark -r cap.pcap -Y 'dns.flags.rcode == 3' | wc -l
# IN PACKET ORDER (do NOT sort - order is the message)
tshark -r cap.pcap -Y 'dns.flags.response == 0 && dns.qry.name contains "tunnel.example"' \
  -T fields -e frame.number -e dns.qry.name > queries.txt
# strip the parent domain and the dots, then decode
cut -d' ' -f2 queries.txt | sed 's/\.tunnel\.example$//' | tr -d '.\n' > blob.b32
# base32 needs uppercase and padding to a multiple of 8
python3 -c "import base64,sys;d=open('blob.b32').read().strip().upper();d+='='*(-len(d)%8);sys.stdout.buffer.write(base64.b32decode(d,casefold=True))" > out.bin
file out.bin && head -c 200 out.bin
# base64 variant
tr -d '.\n' < labels.txt | base64 -d > out.bin
# hex variant
tr -d '.\n' < labels.txt | xxd -r -p > out.bin
# TXT answers carry the return channel
tshark -r cap.pcap -Y 'dns.txt' -T fields -e dns.qry.name -e dns.txt
# NULL records (iodine's preferred type) show as raw data
tshark -r cap.pcap -Y 'dns.qry.type == 10' -T fields -e dns.resp.len -e data.data
# zeek makes the aggregate view trivial
zeek -r cap.pcap && cat dns.log | zeek-cut query qtype_name rcode_name \
  | awk '{print $1}' | rev | cut -d. -f1,2 | rev | sort | uniq -c | sort -rn | head
```

### Chunk ordering

Well-built tunnels put a sequence number in the first label so out-of-order DNS does not corrupt
the stream. Look for a short fixed-width label at a fixed position:

```
0000-<data>.tunnel.example
0001-<data>.tunnel.example
```

If you see that, sort by the sequence field, not by packet order. If you see no sequence field,
packet order is the only ordering you have.

## ICMP tunnelling

```sh
# all ICMP, with the type/code and payload length
tshark -r cap.pcap -Y icmp -T fields -e frame.number -e ip.src -e ip.dst \
  -e icmp.type -e icmp.code -e icmp.ident -e icmp.seq -e data.len
# payload of every echo request, in packet order, concatenated
tshark -r cap.pcap -Y 'icmp.type == 8' -T fields -e data.data | tr -d ':\n' | xxd -r -p > icmp.bin
file icmp.bin && strings icmp.bin | head
# echo replies carry the return channel
tshark -r cap.pcap -Y 'icmp.type == 0' -T fields -e data.data | tr -d ':\n' | xxd -r -p > icmp_back.bin
# a normal Linux ping payload is 8 bytes of timestamp then 0x10..0x37 incrementing
tshark -r cap.pcap -Y 'icmp.type == 8' -T fields -e data.data | head -3
# requests with no matching reply = one-way exfil
tshark -r cap.pcap -Y 'icmp.type == 8' -T fields -e icmp.seq | sort -n > req.txt
tshark -r cap.pcap -Y 'icmp.type == 0' -T fields -e icmp.seq | sort -n > rep.txt
comm -23 req.txt rep.txt | head
# the id and seq fields themselves can carry two bytes each
tshark -r cap.pcap -Y icmp -T fields -e icmp.ident -e icmp.seq \
  | awk '{printf "%04x%04x", $1, $2}' | xxd -r -p
# abnormally large payloads
tshark -r cap.pcap -Y 'icmp && data.len > 64' -T fields -e frame.number -e data.len
```

Known tools: `ptunnel` (TCP over ICMP, has a magic `0xD5200880` in the payload header),
`icmpsh` (shell over echo request/reply, plaintext command output in the payload),
`hans` (IP over ICMP, looks like a tun interface), `icmptunnel`.

## Other channels

```sh
# HTTP header / cookie exfil: unusually long or high-entropy header values
tshark -r cap.pcap -Y http.cookie -T fields -e http.host -e http.cookie \
  | awk 'length($0) > 200'
tshark -r cap.pcap -Y http.user_agent -T fields -e http.user_agent | sort | uniq -c | sort -rn
# data in the URI path/query
tshark -r cap.pcap -Y http.request -T fields -e http.request.uri | awk 'length($0) > 120'
# TCP ISN: 32 bits per SYN, requires a lot of SYNs to move data
tshark -r cap.pcap -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e tcp.seq_raw
# TCP urgent pointer, normally 0 and unused
tshark -r cap.pcap -Y 'tcp.flags.urg == 1 || tcp.urgent_pointer != 0' \
  -T fields -e frame.number -e tcp.urgent_pointer
# IP identification field: 16 bits per packet
tshark -r cap.pcap -T fields -e ip.id | head -40
# TTL encoding: a normally constant field that varies
tshark -r cap.pcap -T fields -e ip.ttl | sort | uniq -c
# TCP timestamp low bits
tshark -r cap.pcap -Y tcp.options.timestamp -T fields -e tcp.options.timestamp.tsval
# IP options and IPv6 extension headers (almost never legitimately used)
tshark -r cap.pcap -Y 'ip.hdr_len > 20' -T fields -e frame.number -e ip.opt.type
tshark -r cap.pcap -Y 'ipv6.nxt == 0 || ipv6.nxt == 60' -T fields -e frame.number
# unused/reserved flag bits
tshark -r cap.pcap -Y 'ip.flags.rb == 1' -T fields -e frame.number
# port knocking: a burst of SYNs to closed ports in a fixed order
tshark -r cap.pcap -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields -e frame.time_relative -e ip.src -e tcp.dstport | head -40
# timing channel: inter-arrival deltas cluster around two values (a 0 and a 1)
tshark -r cap.pcap -Y 'ip.src == 10.0.0.5' -T fields -e frame.time_delta_displayed \
  | sort -n | uniq -c | sort -rn | head
# NTP: the transmit/reference timestamp fields have 32 spare low bits
tshark -r cap.pcap -Y ntp -T fields -e ntp.xmt
# DoH / DoT: DNS hidden inside TLS to 443/853
tshark -r cap.pcap -Y 'tcp.port == 853 || (tls.handshake.extensions_server_name contains "dns")'
# something on 443 that is not TLS (first bytes should be 16 03 0x)
tshark -r cap.pcap -Y 'tcp.port == 443 && tcp.len > 0 && !(tls)' \
  -T fields -e frame.number -e data.data | head
# SMB named pipes used as a transport
tshark -r cap.pcap -Y 'smb2.filename contains "pipe" || smb.file contains "\\PIPE\\"'
```

## Detection heuristics

Score a domain on:

- **Unique subdomain count** -- legitimate domains reuse names; tunnels never repeat.
- **Mean label length** -- normal labels are 3-12 characters; tunnel labels are 30-63.
- **Character-set entropy** -- base32 data is close to uniform over 32 symbols (~5 bits/char);
  English hostnames are far lower.
- **Query-to-answer ratio** -- tunnels get NXDOMAIN or tiny answers constantly.
- **Query rate** -- hundreds per minute to one domain.
- **Record types** -- TXT, NULL and CNAME dominate instead of A/AAAA.

## Code

```python
#!/usr/bin/env python3
"""Score DNS domains for exfiltration and reassemble the top one.

    pip install scapy
    python3 dns_exfil.py capture.pcap
    python3 dns_exfil.py capture.pcap --domain tunnel.example --out recovered.bin
    python3 dns_exfil.py --selftest

Scoring uses the unique-label count, mean label length and Shannon entropy of the
label alphabet. Then it concatenates the non-parent labels in packet order and
tries base32, base64, base16 and raw ascii, printing whichever decodes cleanly.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import collections
import math
import re
import sys

LABEL_OK = re.compile(r"^[A-Za-z0-9_-]+$")


def entropy(text: str) -> float:
    """Shannon entropy of the character distribution, in bits per character."""
    if not text:
        return 0.0
    counts = collections.Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parent_domain(name: str, depth: int = 2) -> str:
    parts = [p for p in name.strip(".").split(".") if p]
    return ".".join(parts[-depth:]) if len(parts) >= depth else name.strip(".")


def collect(pcap: str) -> list[tuple[int, str, int]]:
    """Return [(frame_no, qname, qtype)] for every DNS query, in capture order."""
    try:
        from scapy.all import PcapReader  # type: ignore
        from scapy.layers.dns import DNS, DNSQR  # type: ignore
    except ImportError:
        print("scapy is required:  pip install scapy", file=sys.stderr)
        raise SystemExit(1)

    out: list[tuple[int, str, int]] = []
    with PcapReader(pcap) as reader:
        for i, pkt in enumerate(reader, 1):
            if not pkt.haslayer(DNS):
                continue
            dns = pkt[DNS]
            if getattr(dns, "qr", 1) != 0 or not pkt.haslayer(DNSQR):
                continue
            try:
                qname = dns[DNSQR].qname.decode("latin-1").rstrip(".")
            except (AttributeError, UnicodeDecodeError):
                continue
            out.append((i, qname, int(getattr(dns[DNSQR], "qtype", 0))))
    return out


def score_domains(queries: list[tuple[int, str, int]]) -> list[tuple[str, dict[str, float]]]:
    by_parent: dict[str, list[str]] = collections.defaultdict(list)
    types: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for _, qname, qtype in queries:
        parent = parent_domain(qname)
        prefix = qname[:-len(parent)].rstrip(".") if qname.endswith(parent) else qname
        by_parent[parent].append(prefix)
        types[parent][qtype] += 1

    results: list[tuple[str, dict[str, float]]] = []
    for parent, prefixes in by_parent.items():
        nonempty = [p for p in prefixes if p]
        if not nonempty:
            continue
        labels = [lab for p in nonempty for lab in p.split(".") if lab]
        if not labels:
            continue
        unique = len(set(nonempty))
        mean_len = sum(len(lab) for lab in labels) / len(labels)
        ent = entropy("".join(labels))
        odd_types = sum(c for t, c in types[parent].items() if t in (10, 16, 5))
        ratio = odd_types / max(1, sum(types[parent].values()))
        score = (min(unique, 500) / 5.0
                 + max(0.0, mean_len - 8) * 4.0
                 + max(0.0, ent - 3.0) * 12.0
                 + ratio * 25.0)
        results.append((parent, {
            "queries": float(len(prefixes)),
            "unique": float(unique),
            "mean_label_len": round(mean_len, 1),
            "entropy": round(ent, 2),
            "txt_null_cname_ratio": round(ratio, 2),
            "score": round(score, 1),
        }))
    results.sort(key=lambda kv: -kv[1]["score"])
    return results


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for c in data if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(data)


def try_decodes(blob: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    compact = re.sub(r"[^A-Za-z0-9+/=_-]", "", blob)

    b32 = compact.upper().replace("-", "").replace("_", "")
    b32 += "=" * (-len(b32) % 8)
    try:
        out.append(("base32", base64.b32decode(b32, casefold=True)))
    except (binascii.Error, ValueError):
        pass

    b64 = compact.replace("-", "+").replace("_", "/")
    b64 += "=" * (-len(b64) % 4)
    try:
        out.append(("base64", base64.b64decode(b64, validate=False)))
    except (binascii.Error, ValueError):
        pass

    hexpart = re.sub(r"[^0-9a-fA-F]", "", compact)
    if len(hexpart) >= 4:
        if len(hexpart) % 2:
            hexpart = hexpart[:-1]
        try:
            out.append(("hex", binascii.unhexlify(hexpart)))
        except binascii.Error:
            pass

    out.append(("raw-ascii", compact.encode("latin-1", "replace")))
    return out


def reassemble(queries: list[tuple[int, str, int]], domain: str) -> str:
    parts: list[str] = []
    for _, qname, _ in queries:
        if not qname.endswith(domain):
            continue
        prefix = qname[:-len(domain)].rstrip(".")
        for lab in prefix.split("."):
            if lab and LABEL_OK.match(lab):
                parts.append(lab)
    return "".join(parts)


def selftest() -> int:
    secret = b"flag{dns_exfiltration_is_loud}"
    encoded = base64.b32encode(secret).decode().rstrip("=").lower()
    chunks = [encoded[i:i + 20] for i in range(0, len(encoded), 20)]
    fake = [(i, f"{c}.tunnel.example", 16) for i, c in enumerate(chunks, 1)]
    fake += [(100 + i, f"www{i}.normal.example", 1) for i in range(5)]
    ranked = score_domains(fake)
    assert ranked[0][0] == "tunnel.example", ranked
    blob = reassemble(fake, "tunnel.example")
    results = try_decodes(blob)
    assert any(secret in data for _, data in results), [r[0] for r in results]
    assert round(entropy("aaaa"), 2) == 0.0
    assert 0.99 < entropy("ab") < 1.01
    print("self-test OK -> recovered", secret.decode())
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--domain", help="reassemble this parent domain instead of the top-scored one")
    ap.add_argument("--out", help="write the best decode to this file")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.pcap:
        return selftest()

    queries = collect(args.pcap)
    if not queries:
        print("no DNS queries in this capture", file=sys.stderr)
        return 1
    print(f"== {len(queries)} DNS queries")

    ranked = score_domains(queries)
    print(f"\n{'score':>7} {'queries':>8} {'unique':>7} {'meanlen':>8} {'entropy':>8}  domain")
    for domain, stats in ranked[:args.top]:
        print(f"{stats['score']:>7} {int(stats['queries']):>8} {int(stats['unique']):>7} "
              f"{stats['mean_label_len']:>8} {stats['entropy']:>8}  {domain}")

    target = args.domain or (ranked[0][0] if ranked else None)
    if not target:
        return 0
    print(f"\n== reassembling labels under {target} (packet order)")
    blob = reassemble(queries, target)
    print(f"   {len(blob)} characters of label data")
    if not blob:
        return 0

    best: tuple[str, bytes] | None = None
    for name, data in try_decodes(blob):
        ratio = printable_ratio(data)
        preview = data[:120].decode("latin-1", "replace")
        preview = "".join(c if 32 <= ord(c) < 127 else "." for c in preview)
        print(f"   {name:<10} {len(data):>7} bytes  printable={ratio:.2f}  {preview}")
        if ratio > 0.85 and (best is None or len(data) > len(best[1])):
            best = (name, data)
    if best and args.out:
        with open(args.out, "wb") as fh:
            fh.write(best[1])
        print(f"\n[+] wrote the {best[0]} decode ({len(best[1])} bytes) to {args.out}")
    elif not best:
        print("\n[!] nothing decoded cleanly; the payload is probably encrypted or "
              "uses a custom alphabet - check for a sequence-number label and reorder")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Do not sort the queries.** Packet order carries the message unless there is an explicit
  sequence field. `sort -u` destroys the data.
- The **parent domain may be three labels** (`tun.corp.example`). Strip until the remaining
  prefix stops looking random.
- Base32 in DNS is usually **lowercase and unpadded**; uppercase it and pad to a multiple of 8
  before decoding.
- A **custom alphabet** (base36, base128, a substitution) will defeat every standard decoder.
  Look at the character histogram: 32 distinct symbols means base32, 64 means base64, 16 means hex.
- **Retransmitted queries** duplicate chunks. Deduplicate on the full qname while preserving
  first-seen order.
- The exfiltrated data may be **compressed or encrypted** before encoding -- a clean decode that
  produces high-entropy bytes is still progress. Run `file` and `binwalk` on it.
- ICMP payload from a real `ping` has a timestamp in the first 8 bytes; strip it before decoding.
- A timing channel leaves **no payload at all**. If every field looks clean, plot the
  inter-arrival deltas.
- DoH hides the whole thing inside TLS. Without keys you see only the volume and the SNI.

## Tools

`tshark`/`wireshark`, `zeek` (dns.log, conn.log), `scapy`, `ngrep`, `python3`,
`iodine`/`dnscat2`/`dns2tcp`/`dnsteal` (to reproduce the traffic), `xxd`, `base32`/`base64`.

## References

- `tshark -G fields | grep '^F\tdns'` and `grep '^F\ticmp'` list every field name you can extract.
- RFC 1035 section 2.3.1 defines the 63-byte label and 255-byte name limits that shape every DNS
  tunnel's chunk size.
