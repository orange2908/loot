---
title: "PCAP Triage - The First Ten Commands"
category: forensics
subcategory: network
type: technique
tags: [pcap, pcapng, tshark, wireshark, capinfos, editcap, mergecap, tcpdump, tcpflow, ngrep, zeek, bro, networkminer, protocol-hierarchy, export-objects, follow-stream, scapy, dfir]
difficulty: easy
summary: "Ten commands that tell you what is in a capture in under two minutes: protocol hierarchy, conversations, exported objects, and a flag grep."
when_to_use:
  - "You were handed a .pcap / .pcapng / .cap / .snoop and nothing else"
  - "The challenge says 'we captured the attacker's traffic'"
  - "You need to know which protocols are present before picking a deeper technique"
  - "A file was transferred over the wire and you must recover it"
tools: [tshark, wireshark, capinfos, editcap, mergecap, tcpdump, tcpflow, ngrep, zeek, networkminer, scapy, foremost, binwalk]
related: [network-extract-files-creds, network-tls-decryption, network-covert-channels, network-c2-analysis, network-scapy-analysis]
---

## TL;DR

`capinfos` for the shape, `-z io,phs` for what protocols exist, `-z conv,tcp` for who talked to
whom, `--export-objects` for the files, and `strings | grep flag` because it works more often than
it should. Do all five before you open the GUI.

## Recognise it

- `file cap.pcap` -> `pcap capture file` (magic `d4c3b2a1` / `a1b2c3d4`, or `4d3cb2a1` for
  nanosecond pcap). `.pcapng` -> `pcapng capture file` (magic `0a0d0d0a`).
- `capinfos` refuses the file -> it may be a `.cap` from a different tool, a snoop file, or
  truncated. Try `editcap -F pcap in out` or `tcpdump -r` to confirm.
- A `.pcapng` may carry **embedded TLS secrets** (Decryption Secrets Blocks) -- check for them.

## The ten commands

```sh
# 1) shape of the capture: packet count, duration, start/end time, link type, capture length
capinfos capture.pcap
# 2) what protocols are actually present, with byte counts - your roadmap
tshark -r capture.pcap -q -z io,phs
# 3) who talked to whom, ranked by bytes (also conv,udp / conv,ip / conv,eth)
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z conv,udp
# 4) endpoint totals, useful for spotting the one external IP that matters
tshark -r capture.pcap -q -z endpoints,ip
# 5) every HTTP request in one line each
tshark -r capture.pcap -Y http.request -T fields -e frame.number -e ip.src -e http.host -e http.request.method -e http.request.uri
# 6) every DNS name queried, deduplicated
tshark -r capture.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u
# 7) pull out every file the capture carried
mkdir -p objs && tshark -r capture.pcap -q --export-objects http,objs
tshark -r capture.pcap -q --export-objects smb,objs_smb
tshark -r capture.pcap -q --export-objects imf,objs_mail      # email messages
tshark -r capture.pcap -q --export-objects tftp,objs_tftp
tshark -r capture.pcap -q --export-objects dicom,objs_dicom
# 8) the blunt flag grep - do it early, it costs nothing
strings -a capture.pcap | grep -aoiE '[a-z0-9_]{2,16}\{[^}]{4,120}\}' | sort -u
# 9) Wireshark's own anomaly list: malformed packets, retransmissions, resets
tshark -r capture.pcap -q -z expert
# 10) dump one whole conversation as text (stream index 0)
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

## Reading the protocol hierarchy

`-z io,phs` output is a tree with frame/byte counts. What to look for:

- `data` with a large byte count and no higher-layer protocol -> a raw TCP protocol, likely the
  challenge. Follow that stream.
- `tls` dominant and `http` absent -> go to the TLS decryption technique.
- `dns` with an unusually high frame count relative to bytes -> DNS tunnelling.
- `icmp` carrying kilobytes -> ICMP tunnelling.
- `usb` / `usbhid` -> USB HID capture.
- `ieee80211` / `radiotap` -> wireless capture.
- `smb2`, `ftp-data`, `tftp`, `imf` -> file transfer, export objects.
- `http2`, `quic` -> modern web, needs keys.

## Conversations and stream indices

```sh
# list TCP streams with their index (the number you pass to follow,tcp,ascii,N)
tshark -r capture.pcap -T fields -e tcp.stream | sort -un | tail -1   # highest stream index
# map stream index -> endpoints
tshark -r capture.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
# dump every stream to its own file
for i in $(tshark -r capture.pcap -T fields -e tcp.stream | sort -un); do
  tshark -r capture.pcap -q -z follow,tcp,raw,$i > "stream_$i.raw"
done
# the same thing, but tcpflow does it in one shot and names files by endpoints
tcpflow -r capture.pcap -o flows/
ls flows/
# and it can print a report of what it saw
tcpflow -r capture.pcap -o flows/ -c | head -50
```

## Field extraction recipes

```sh
# -T fields with -E to get a proper CSV you can pipe into anything
tshark -r capture.pcap -T fields -E header=y -E separator=, -E quote=d \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e _ws.col.Protocol \
  > packets.csv
# occurrences: some fields repeat per packet; -E occurrence=a joins them all
tshark -r capture.pcap -Y dns -T fields -E occurrence=a -e dns.qry.name -e dns.a
# hex payload of a field, then convert to bytes
tshark -r capture.pcap -Y 'ftp-data' -T fields -e data.data | tr -d ':\n' | xxd -r -p > ftpdata.bin
# the column view exactly as the GUI renders it
tshark -r capture.pcap -T fields -e _ws.col.Info -e _ws.col.Source -e _ws.col.Destination
```

## Converting, splitting, merging

```sh
# pcapng -> pcap (needed by older tools like aircrack-ng or some carvers)
editcap -F pcap in.pcapng out.pcap
# split a huge capture into 100k-packet chunks
editcap -c 100000 big.pcap chunk.pcap
# split by time (3600 seconds per file)
editcap -i 3600 big.pcap hour.pcap
# cut a time window out
editcap -A "2024-01-15 12:00:00" -B "2024-01-15 12:30:00" in.pcap window.pcap
# keep only packets 100-200
editcap -r in.pcap out.pcap 100-200
# merge in timestamp order
mergecap -w all.pcap part1.pcap part2.pcap part3.pcap
# strip duplicates introduced by a span port
editcap -d in.pcap dedup.pcap
# truncate each packet to its headers (faster greps)
editcap -s 96 in.pcap short.pcap
# fix a capture with a broken snaplen or bad link type
editcap -T ether in.pcap fixed.pcap
```

## Alternatives to tshark

```sh
# tcpdump for a quick look without Wireshark installed
tcpdump -r capture.pcap -nn -q | head -50
# print full packet payloads as hex+ascii
tcpdump -r capture.pcap -nn -X 'tcp port 80' | head -100
# ngrep: grep across packet payloads, line-oriented output
ngrep -I capture.pcap -q -W byline 'password'
ngrep -I capture.pcap -q -W byline -i 'flag|secret|token'
# ngrep restricted by BPF
ngrep -I capture.pcap -q -W byline '' 'tcp port 21'
# zeek turns a pcap into a directory of structured logs
mkdir zeeklogs && cd zeeklogs && zeek -r ../capture.pcap
ls   # conn.log dns.log http.log files.log ssl.log x509.log weird.log notice.log
# zeek-cut pulls named columns out of a zeek log
cat http.log | zeek-cut ts id.orig_h id.resp_h host uri user_agent | head -40
cat dns.log  | zeek-cut query qtype_name answers | sort -u | head -40
cat files.log | zeek-cut ts source mime_type filename md5 sha1
cat ssl.log  | zeek-cut server_name ja3 ja3s subject issuer
# zeek can also carve every transferred file out for you
zeek -r ../capture.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
ls extract_files/
# NetworkMiner (GUI/CLI, mono on Linux): automatic file, credential and host extraction
mono /opt/NetworkMiner/NetworkMinerCLI.exe -r capture.pcap
# brute carve: sometimes a file is in there but no protocol dissector found it
foremost -t all -i capture.pcap -o carved
binwalk -e capture.pcap
```

## Wireshark GUI equivalents

| Task | GUI path |
| --- | --- |
| Protocol hierarchy | Statistics > Protocol Hierarchy |
| Conversations | Statistics > Conversations (tick "Limit to display filter") |
| Endpoints | Statistics > Endpoints |
| HTTP requests | Statistics > HTTP > Requests |
| DNS tree | Statistics > DNS |
| Expert info | Analyze > Expert Information |
| Follow a stream | right-click packet > Follow > TCP/UDP/HTTP/TLS Stream |
| Export files | File > Export Objects > HTTP / SMB / IMF / TFTP / DICOM |
| Force a dissector | right-click > Decode As... |
| Absolute timestamps | View > Time Display Format > UTC Date and Time of Day |
| Search payload bytes | Edit > Find Packet > Packet bytes > String |
| Global payload filter | `frame contains "flag"` or `frame matches "(?i)flag\{"` |
| TLS keys | Preferences > Protocols > TLS > (Pre)-Master-Secret log filename |
| Show reassembled data | Preferences > Protocols > TCP > Allow subdissector to reassemble |

The single most useful display filter in a CTF:

```
frame contains "flag"
```

and its case-insensitive regex cousin:

```
frame matches "(?i)flag\{"
```

## Code

```python
#!/usr/bin/env python3
"""One-shot pcap triage: protocols, talkers, DNS, HTTP, and flag-shaped strings.

    pip install scapy
    python3 pcap_triage.py capture.pcap [--top 15] [--flag-regex 'flag\\{']

Streams the capture with PcapReader so a multi-gigabyte file does not blow up RAM.
"""
from __future__ import annotations

import argparse
import collections
import re
import sys

try:
    from scapy.all import PcapReader, Raw  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except ImportError:  # pragma: no cover
    print("scapy is required:  pip install scapy", file=sys.stderr)
    raise SystemExit(1)

WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "submission",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 1883: "mqtt", 3306: "mysql", 3389: "rdp", 4444: "metasploit",
    5432: "postgres", 5900: "vnc", 6379: "redis", 6667: "irc", 8080: "http-alt",
    8443: "https-alt", 9001: "tor", 27017: "mongodb",
}
HTTP_REQ = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) (\S+) HTTP/1\.[01]")
HOST_HDR = re.compile(rb"\r\nHost:\s*([^\r\n]+)", re.I)
UA_HDR = re.compile(rb"\r\nUser-Agent:\s*([^\r\n]+)", re.I)


def label_port(sport: int, dport: int) -> str:
    for p in (dport, sport):
        if p in WELL_KNOWN:
            return WELL_KNOWN[p]
    return f"tcp/{min(sport, dport)}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", nargs="?", default="capture.pcap")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--flag-regex", default=r"[A-Za-z0-9_]{2,16}\{[\x20-\x7e]{4,120}\}")
    args = ap.parse_args()

    flag_re = re.compile(args.flag_regex.encode(), re.I)

    protos: collections.Counter[str] = collections.Counter()
    talkers: collections.Counter[tuple[str, str]] = collections.Counter()
    talker_bytes: collections.Counter[tuple[str, str]] = collections.Counter()
    services: collections.Counter[str] = collections.Counter()
    dns_names: collections.Counter[str] = collections.Counter()
    http_reqs: list[str] = []
    user_agents: collections.Counter[str] = collections.Counter()
    flags_found: set[str] = set()
    total = 0
    first_ts = last_ts = None

    try:
        reader = PcapReader(args.pcap)
    except (FileNotFoundError, OSError) as exc:
        print(f"cannot open {args.pcap}: {exc}", file=sys.stderr)
        return 1

    with reader:
        for pkt in reader:
            total += 1
            ts = float(getattr(pkt, "time", 0.0))
            if first_ts is None:
                first_ts = ts
            last_ts = ts

            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                protos["non-ip"] += 1
                continue

            key = tuple(sorted((src, dst)))
            talkers[key] += 1
            talker_bytes[key] += len(pkt)

            if pkt.haslayer(TCP):
                protos["tcp"] += 1
                services[label_port(int(pkt[TCP].sport), int(pkt[TCP].dport))] += 1
            elif pkt.haslayer(UDP):
                protos["udp"] += 1
                services[WELL_KNOWN.get(int(pkt[UDP].dport),
                                        WELL_KNOWN.get(int(pkt[UDP].sport),
                                                       f"udp/{int(pkt[UDP].dport)}"))] += 1
            elif pkt.haslayer(ICMP):
                protos["icmp"] += 1
            else:
                protos["other-ip"] += 1

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                try:
                    dns_names[pkt[DNSQR].qname.decode(errors="replace").rstrip(".")] += 1
                except (AttributeError, UnicodeDecodeError):
                    pass

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                m = HTTP_REQ.match(payload)
                if m:
                    host = HOST_HDR.search(payload)
                    hostname = host.group(1).decode(errors="replace") if host else "?"
                    http_reqs.append(f"{m.group(1).decode()} http://{hostname}"
                                     f"{m.group(2).decode(errors='replace')}")
                    ua = UA_HDR.search(payload)
                    if ua:
                        user_agents[ua.group(1).decode(errors="replace")] += 1
                for hit in flag_re.findall(payload):
                    flags_found.add(hit.decode("latin-1"))

    print(f"== {args.pcap}: {total} packets", end="")
    if first_ts and last_ts:
        print(f", {last_ts - first_ts:.1f}s span")
    else:
        print()

    print("\n== protocols")
    for name, count in protos.most_common():
        print(f"  {count:>8}  {name}")

    print("\n== services (by packet count)")
    for name, count in services.most_common(args.top):
        print(f"  {count:>8}  {name}")

    print("\n== top talkers (by bytes)")
    for (a, b), nbytes in talker_bytes.most_common(args.top):
        print(f"  {nbytes:>12} B  {talkers[(a, b)]:>7} pkts  {a} <-> {b}")

    if dns_names:
        print("\n== dns queries")
        for name, count in dns_names.most_common(args.top):
            print(f"  {count:>6}  {name}")

    if http_reqs:
        print(f"\n== http requests ({len(http_reqs)} total, first {args.top})")
        for line in http_reqs[:args.top]:
            print(f"  {line}")

    if user_agents:
        print("\n== user agents")
        for ua, count in user_agents.most_common(args.top):
            print(f"  {count:>6}  {ua}")

    if flags_found:
        print("\n== flag-shaped strings in payloads")
        for f in sorted(flags_found):
            print(f"  {f}")
    else:
        print("\n== no flag-shaped strings in cleartext payloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **`--export-objects` misses a lot.** It only reassembles what the dissector understood. If a
  download was chunked, gzipped and split across a TCP gap, export the raw stream instead and
  carve by hand.
- **Truncated captures**: `capinfos` shows a snaplen of 68 or 96 -> only headers were captured.
  No payloads exist. Stop looking for file content.
- **A "corrupted" pcap** often just has a wrong link-type. `editcap -T ether` or open it with
  `Decode As` in the GUI.
- `tshark` needs read permission on the file *and* on `/usr/bin/dumpcap` in some packagings; if
  you get a permissions error on a file you can `cat`, that is why.
- `-Y` is the **display** filter (after dissection); `-f` is the **capture** BPF filter and is
  ignored when reading a file. Always use `-Y` with `-r`.
- Protocols on non-standard ports are not dissected. Force it:
  `tshark -r f.pcap -d tcp.port==4444,http -Y http`.
- A `.pcapng` with Decryption Secrets Blocks decrypts TLS with no extra flags. Check with
  `capinfos -a` / `tshark -r f.pcapng -Y tls.record.content_type` before hunting for keys.

## Tools

`tshark`, `wireshark`, `capinfos`, `editcap`, `mergecap`, `tcpdump`, `tcpflow`, `ngrep`,
`zeek` + `zeek-cut`, `NetworkMiner`, `scapy`, `foremost`, `binwalk`, `PCredz`, `chaosreader`.

## References

- `man tshark`, `man editcap`, `man capinfos` -- the `-z` statistics taps are all documented there.
- `tshark -G fields` dumps every display-filter field name your build knows.
