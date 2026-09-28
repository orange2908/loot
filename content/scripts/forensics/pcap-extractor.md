---
title: "PCAP Extractor - Objects, Credentials, DNS and Streams"
category: forensics
subcategory: network
type: script
tags: [pcap, scapy, tshark, http, ftp, telnet, smtp, dns, credentials, tcp-reassembly, file-carving, network-forensics, python, dfir, wireshark, imap, pop3, chunked, gzip]
summary: "One scapy script that reassembles every TCP stream, carves HTTP bodies, dumps cleartext credentials, logs DNS to CSV and greps for the flag."
tools: [python3, scapy, tshark, wireshark, networkminer, foremost]
related: [network-pcap-triage, network-extract-files-creds, network-scapy-analysis, tshark-wireshark-cheatsheet, carve-and-identify]
---

## What it does

Replaces the "Export Objects, then Follow TCP Stream forty times" phase of a pcap challenge
with one pass. It streams the capture with `PcapReader` (constant memory), rebuilds every TCP
half-conversation from raw sequence numbers, then runs four extractors over the rebuilt bytes:
HTTP object carving (Content-Length, chunked, gzip/deflate), credential harvesting (HTTP
Basic/Bearer/form, FTP, telnet, SMTP/IMAP/POP3 AUTH), DNS to CSV, and a flag grep in ASCII and
UTF-16LE. Object names carry a short sha256 so nothing clobbers anything under `<outdir>/`.

## Usage

```bash
# full run (needs `pip install scapy`): writes streams/, objects/, dns.csv + a summary table
python3 pcap_extractor.py capture.pcap --outdir loot
# a challenge whose flag wrapper is not the default one
python3 pcap_extractor.py capture.pcap --outdir loot --flag-regex 'HTB\{[^}]+\}'
# huge capture: cap each direction at 4 MiB, skip HTTP body carving
python3 pcap_extractor.py big.pcapng --outdir loot --max-stream-bytes 4194304 --no-objects
# verify the tool itself - builds its own pcap, needs no input file
python3 pcap_extractor.py --selftest
# triage what came out
file loot/objects/* && grep -raoE 'flag\{[^}]+\}' loot/
```

## Script

```python
#!/usr/bin/env python3
"""Streaming pcap extractor: TCP streams, HTTP objects, credentials, DNS, flags.

Reads the capture with scapy's PcapReader one packet at a time, reassembles every
TCP conversation by sequence number (retransmits, reordering and overlap included),
parses HTTP out of it, harvests cleartext credentials, logs DNS to a CSV, and greps
every stream for a flag regex in ASCII and UTF-16LE.   Needs scapy: pip install scapy
"""
from __future__ import annotations

import argparse, base64, binascii, csv, gzip, hashlib, os, re, sys, zlib
from collections import defaultdict

try:
    from scapy.all import (DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP, Ether,
                           PcapReader, wrpcap)
    HAVE_SCAPY = True
except ImportError:  # pragma: no cover - depends on the environment
    HAVE_SCAPY = False

WRAP = 1 << 32
DEFAULT_FLAG_RE = r"[A-Za-z0-9_]{2,20}\{[ -~]{2,120}\}"
HDR_END = re.compile(rb"\r?\n\r?\n")
REQ_LINE = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT) (\S+) HTTP/1\.[01]")
RESP_LINE = re.compile(rb"^HTTP/1\.[01] (\d{3})")
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}

class Direction:
    """One half of a TCP conversation: payload segments keyed by relative offset."""
    def __init__(self) -> None:
        self.isn: int | None = None
        self.segments: list[tuple[int, bytes]] = []

    def add(self, seq: int, payload: bytes) -> None:
        if self.isn is None:                         # no SYN seen: first data is offset 0
            self.isn = seq
        self.segments.append(((seq - self.isn) % WRAP, payload))

    def assemble(self, max_bytes: int) -> bytes:
        """First-writer-wins merge of out-of-order/overlapping segments; holes -> NUL."""
        if not self.segments:
            return b""
        base = min(off for off, _ in self.segments)
        size = min(max(off + len(d) for off, d in self.segments) - base, max_bytes)
        if size <= 0:
            return b""
        buf, have = bytearray(size), bytearray(size)
        for off, data in sorted(self.segments):
            start = off - base
            if start >= size:
                continue
            chunk = data[: size - start]
            if 1 not in have[start:start + len(chunk)]:          # no overlap: fast path
                buf[start:start + len(chunk)] = chunk
                have[start:start + len(chunk)] = b"\x01" * len(chunk)
            else:
                for i, byte in enumerate(chunk):
                    if not have[start + i]:
                        buf[start + i], have[start + i] = byte, 1
        return bytes(buf)

def flow_key(pkt):
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    return None if ip is None else (ip.src, int(pkt[TCP].sport), ip.dst, int(pkt[TCP].dport))

def canon(key):
    """Order the endpoints so both directions land in the same conversation."""
    return tuple(sorted(((key[0], key[1]), (key[2], key[3]))))

def split_headers(block: bytes) -> tuple[bytes, dict[str, str]]:
    lines = block.replace(b"\r\n", b"\n").split(b"\n")
    parts = [line.partition(b":") for line in lines[1:]]
    headers = {k.decode("latin-1").strip().lower(): v.decode("latin-1").strip()
               for k, sep, v in parts if sep}
    return (lines[0] if lines else b""), headers

def dechunk(body: bytes) -> bytes:
    out, pos = bytearray(), 0
    while pos < len(body):
        nl = body.find(b"\n", pos)
        if nl < 0:
            break
        try:
            size = int(body[pos:nl].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        pos = nl + 1
        if size == 0:
            break
        out += body[pos:pos + size]
        pos += size
        while pos < len(body) and body[pos] in (13, 10):
            pos += 1
    return bytes(out)

def decompress(body: bytes, encoding: str) -> bytes:
    enc = encoding.lower()
    for attempt in ((gzip.decompress,) if "gzip" in enc else
                    (zlib.decompress, lambda b: zlib.decompress(b, -zlib.MAX_WBITS))
                    if "deflate" in enc else ()):
        try:
            return attempt(body)
        except (OSError, zlib.error, EOFError):
            continue
    return body

def parse_http(buf: bytes) -> list[dict]:
    """Walk one reassembled direction and return every HTTP message found in it."""
    messages, pos = [], 0
    while pos < len(buf):
        req = REQ_LINE.search(buf[pos:pos + 8192])
        head = buf.find(b"HTTP/1.", pos)
        anchor = pos + req.start() if req else None
        if anchor is None and head < 0:
            break
        if anchor is None or 0 <= head < anchor:
            anchor = head
        end = HDR_END.search(buf, anchor)
        if not end:
            break
        start, headers = split_headers(buf[anchor:end.start()])
        body_start = end.end()
        kind = ("request" if REQ_LINE.match(start) else
                "response" if RESP_LINE.match(start) else None)
        if kind is None:
            pos = body_start
            continue
        clen = headers.get("content-length")
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = dechunk(buf[body_start:])
            nxt = buf.find(b"0\r\n\r\n", body_start)
            pos = nxt + 5 if nxt >= 0 else len(buf)
        elif clen is not None and clen.isdigit():
            body, pos = buf[body_start:body_start + int(clen)], body_start + int(clen)
        elif kind == "response":
            body, pos = buf[body_start:], len(buf)
        else:
            body, pos = b"", body_start
        messages.append({"kind": kind, "start": start.decode("latin-1", "replace"),
                         "headers": headers,
                         "body": decompress(body, headers.get("content-encoding", ""))})
    return messages

def object_name(uri: str, body: bytes) -> str:
    tail = uri.split("?")[0].rstrip("/").rsplit("/", 1)[-1] or "index"
    return f"{SAFE_NAME.sub('_', tail)[:60]}_{hashlib.sha256(body).hexdigest()[:8]}"

CRED_LINE = re.compile(rb"(?im)^(USER|PASS)\s+(.+?)\r?$")   # FTP and POP3 both use it
GENERIC = re.compile(rb"(?i)\b(user(?:name)?|login|pass(?:wo?rd)?|pwd)=([^&\s\"'<>]{1,64})")
AUTH_PLAIN = re.compile(rb"(?i)AUTH\s+PLAIN\s+([A-Za-z0-9+/=]{4,})")
AUTH_LOGIN = re.compile(rb"(?i)AUTH\s+LOGIN\s*\r?\n")
B64_LINE = re.compile(rb"(?m)^([A-Za-z0-9+/]{4,}={0,2})\r?$")

def b64(data: bytes) -> str:
    try:
        return base64.b64decode(data, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return "<undecodable:%s>" % data.decode("latin-1", "replace")[:40]

def strip_telnet(buf: bytes) -> str:
    """Drop IAC negotiation and NULs so only the characters typed remain."""
    out, i = bytearray(), 0
    while i < len(buf):
        if buf[i] == 0xFF:                            # IAC
            if buf[i:i + 2] == b"\xff\xfa":           # subnegotiation runs to IAC SE
                end = buf.find(b"\xff\xf0", i + 2)
                i = end + 2 if end >= 0 else len(buf)
            else:
                i += 3                                # IAC WILL/WONT/DO/DONT x
        else:
            if buf[i] not in (0, 13):
                out.append(buf[i])
            i += 1
    return out.decode("latin-1", "replace")

def creds_from_stream(label: str, ports: set[int], c2s: bytes, s2c: bytes) -> list[tuple]:
    found = []
    for msg in parse_http(c2s):
        auth = msg["headers"].get("authorization", "")
        if auth.lower().startswith("basic "):
            found.append((label, "http-basic", b64(auth.split(None, 1)[1].encode())))
        elif auth.lower().startswith("bearer "):
            found.append((label, "http-bearer", auth.split(None, 1)[1][:200]))
        if msg["start"].startswith("POST") and msg["body"]:
            found.append((label, "http-post-body", msg["body"][:300].decode("latin-1", "replace")))
    for proto, port in (("ftp", 21), ("mail", 110)):
        if port in ports or (proto == "mail" and ports & MAIL_PORTS):
            found += [(label, f"{proto}-" + m.group(1).decode().lower(),
                       m.group(2).decode("latin-1", "replace")) for m in CRED_LINE.finditer(c2s)]
    if 23 in ports and strip_telnet(c2s).strip():
        found.append((label, "telnet-input", strip_telnet(c2s)[:300]))
    if ports & MAIL_PORTS:
        found += [(label, "auth-plain", b64(m.group(1)).replace("\x00", ":"))
                  for m in AUTH_PLAIN.finditer(c2s)]
        if AUTH_LOGIN.search(c2s):
            found += [(label, "auth-login", b64(m.group(1))) for m in B64_LINE.finditer(c2s)]
    found += [(label, "generic-" + m.group(1).decode().lower(),
               m.group(2).decode("latin-1", "replace"))
              for m in GENERIC.finditer(c2s + b"\n" + s2c)]
    return list(dict.fromkeys(found))      # stable de-duplication

def grep_flags(buf: bytes, rx: re.Pattern) -> set[str]:
    """ASCII hits plus both byte alignments of UTF-16LE."""
    hits = {m.group(0).decode("latin-1", "replace") for m in rx.finditer(buf)}
    for off in (0, 1):
        wide = buf[off:].decode("utf-16-le", "ignore").encode("latin-1", "ignore")
        hits |= {m.group(0).decode("latin-1", "replace") for m in rx.finditer(wide)}
    return hits

def dns_row(frame: int, dns) -> list[str]:
    qd, answers = dns.qd, []
    qname = bytes(qd.qname).decode("latin-1").rstrip(".") if qd is not None else ""
    qtype = int(qd.qtype) if qd is not None else 0
    for i in range(int(dns.ancount or 0)):
        try:
            rd = dns.an[i].rdata
        except (IndexError, TypeError, AttributeError):
            break
        answers.append(rd.decode("latin-1").rstrip(".") if isinstance(rd, bytes) else str(rd))
    return [str(frame), "response" if dns.qr else "query", qname, str(qtype), "|".join(answers)]

def extract(pcap: str, outdir: str, flag_rx: re.Pattern, max_stream: int,
            want_objects: bool = True, quiet: bool = False) -> dict:
    dirs: dict[tuple, Direction] = defaultdict(Direction)
    dns_rows, packets = [], 0
    os.makedirs(os.path.join(outdir, "streams"), exist_ok=True)
    if want_objects:
        os.makedirs(os.path.join(outdir, "objects"), exist_ok=True)
    with PcapReader(pcap) as reader:
        for pkt in reader:
            packets += 1
            if pkt.haslayer(TCP):
                key, tcp = flow_key(pkt), pkt[TCP]
                if key is None:
                    continue
                if tcp.flags & 0x02 and not tcp.flags & 0x10:     # SYN, not SYN/ACK
                    dirs[key].isn = (int(tcp.seq) + 1) % WRAP
                payload = bytes(tcp.payload)
                if payload:
                    dirs[key].add(int(tcp.seq), payload)
            elif pkt.haslayer(DNS):
                dns_rows.append(dns_row(packets, pkt[DNS]))

    convs: dict[tuple, dict] = defaultdict(dict)
    for key, direction in dirs.items():
        convs[canon(key)][key] = direction
    streams, objects, creds, flags = 0, 0, [], set()
    for pair, halves in sorted(convs.items()):
        (ip_a, pa), (ip_b, pb) = pair
        label, ports, buffers = f"{ip_a}:{pa}-{ip_b}:{pb}", {pa, pb}, {}
        for key, direction in halves.items():
            data = direction.assemble(max_stream)
            if not data:
                continue
            buffers[key] = data
            streams += 1
            name = f"{key[0]}_{key[1]}-{key[2]}_{key[3]}.bin".replace(":", "-")
            with open(os.path.join(outdir, "streams", name), "wb") as fh:
                fh.write(data)
            flags |= grep_flags(data, flag_rx)
        if not buffers:
            continue
        server_port = min(ports) if min(ports) < 1024 else max(ports)
        c2s = b"".join(v for k, v in buffers.items() if k[3] == server_port)
        s2c = b"".join(v for k, v in buffers.items() if k[1] == server_port)
        creds += creds_from_stream(label, ports, c2s, s2c)
        if not want_objects:
            continue
        uris = [m["start"].split()[1] for m in parse_http(c2s)
                if m["kind"] == "request" and len(m["start"].split()) > 1]
        for i, msg in enumerate(m for m in parse_http(s2c) if m["kind"] == "response"):
            if not msg["body"]:
                continue
            uri = uris[i] if i < len(uris) else f"object{i}"
            with open(os.path.join(outdir, "objects", object_name(uri, msg["body"])), "wb") as fh:
                fh.write(msg["body"])
            objects += 1

    if dns_rows:
        with open(os.path.join(outdir, "dns.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["frame", "kind", "name", "qtype", "answers"])
            w.writerows(dns_rows)
    res = {"packets": packets, "conversations": len(convs), "streams": streams,
           "objects": objects, "creds": creds, "dns": dns_rows, "flags": sorted(flags)}
    if not quiet:
        print("=" * 68)
        print(f"packets        : {packets}\n"
              f"conversations  : {len(convs)} ({streams} directional streams)\n"
              f"http objects   : {objects} -> {os.path.join(outdir, 'objects')}\n"
              f"dns records    : {len(dns_rows)} -> {os.path.join(outdir, 'dns.csv')}\n"
              f"credentials    : {len(creds)}")
        for label, kind, value in creds:
            print(f"  {kind:<16} {label:<32} {value!r}")
        print(f"flags          : {len(res['flags'])}")
        print("\n".join("  " + f for f in res["flags"]) or "  (none)")
        print("=" * 68)
    return res

def build_pcap(path: str) -> None:
    """Synthesise a capture: HTTP GET/200 carrying a flag, an FTP login, a DNS lookup."""
    pkts, ip_c, ip_s = [], "10.0.0.5", "10.0.0.9"

    def conv(sport, dport, chunks):
        cseq, sseq = 1000, 500000

        def seg(to_srv, flags, seq, ack, data=b""):
            src, dst = (ip_c, ip_s) if to_srv else (ip_s, ip_c)
            sp, dp = (sport, dport) if to_srv else (dport, sport)
            pkts.append(Ether() / IP(src=src, dst=dst) /
                        TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack) / data)

        seg(True, "S", cseq, 0)
        seg(False, "SA", sseq, cseq + 1)
        cseq, sseq = cseq + 1, sseq + 1
        seg(True, "A", cseq, sseq)
        for side, data in chunks:
            to_srv = side == "c"
            seg(to_srv, "PA", cseq if to_srv else sseq, sseq if to_srv else cseq, data)
            if to_srv:
                cseq += len(data)
            else:
                sseq += len(data)

    body = b"<html><body>flag{pcap_reassembly_works}</body></html>"
    resp = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)
    conv(45678, 80, [("c", b"GET /secret/loot.html HTTP/1.1\r\nHost: ctf.local\r\n"
                           b"Authorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n"),
                     ("s", resp[:20]), ("s", resp[20:])])      # response split in two
    conv(45679, 21, [("s", b"220 ProFTPD Server ready\r\n"), ("c", b"USER ctfuser\r\n"),
                     ("s", b"331 Password required\r\n"), ("c", b"PASS sup3rs3cret\r\n"),
                     ("s", b"230 User logged in\r\n")])
    pkts.append(Ether() / IP(src=ip_c, dst="10.0.0.1") / UDP(sport=51000, dport=53) /
                DNS(rd=1, qd=DNSQR(qname="exfil.ctf.local")))
    pkts.append(Ether() / IP(src="10.0.0.1", dst=ip_c) / UDP(sport=53, dport=51000) /
                DNS(qr=1, qd=DNSQR(qname="exfil.ctf.local"),
                    an=DNSRR(rrname="exfil.ctf.local", type="A", rdata="93.184.216.34")))
    wrpcap(path, pkts)

def selftest() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        pcap, out = os.path.join(tmp, "case.pcap"), os.path.join(tmp, "out")
        build_pcap(pcap)
        res = extract(pcap, out, re.compile(DEFAULT_FLAG_RE.encode()), 1 << 20, True, quiet=True)
        creds = {kind: value for _, kind, value in res["creds"]}
        objs = os.listdir(os.path.join(out, "objects"))
        assert res["packets"] > 10 and len(os.listdir(os.path.join(out, "streams"))) == 4
        assert "flag{pcap_reassembly_works}" in res["flags"], res["flags"]
        assert creds.get("http-basic") == "admin:hunter2", res["creds"]
        assert (creds.get("ftp-user"), creds.get("ftp-pass")) == ("ctfuser", "sup3rs3cret"), res["creds"]
        assert "exfil.ctf.local" in {row[2] for row in res["dns"]}, res["dns"]
        assert any(o.startswith("loot.html_") for o in objs), objs
        with open(os.path.join(out, "objects", objs[0]), "rb") as fh:
            assert b"flag{pcap_reassembly_works}" in fh.read()
    print("selftest ok: reassembly, split http response, basic auth, ftp creds, dns, flag")
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract TCP streams, HTTP objects, credentials, DNS and flags from a pcap.")
    ap.add_argument("pcap", nargs="?", help="capture file (.pcap / .pcapng)")
    ap.add_argument("--outdir", default="pcap_out", help="output directory (default: pcap_out)")
    ap.add_argument("--flag-regex", default=DEFAULT_FLAG_RE, help="flag pattern to grep for")
    ap.add_argument("--max-stream-bytes", type=int, default=32 * 1024 * 1024,
                    help="per-direction reassembly cap in bytes (default 32 MiB)")
    ap.add_argument("--no-objects", action="store_true", help="skip HTTP body carving")
    ap.add_argument("--selftest", action="store_true", help="build a pcap and verify the extractor")
    args = ap.parse_args()
    if not HAVE_SCAPY:
        print("scapy is required:  pip install scapy", file=sys.stderr)
        return 2
    if args.selftest:
        return selftest()
    if not args.pcap:
        ap.error("a pcap path is required (or use --selftest)")
    extract(args.pcap, args.outdir, re.compile(args.flag_regex.encode()),
            args.max_stream_bytes, not args.no_objects)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## Notes

- Reassembly is first-writer-wins on a relative-offset map: a retransmit is a no-op, a reordered
  segment lands where its sequence number says, and an overlap cannot rewrite delivered bytes.
- The ISN comes from the SYN when the handshake is captured, otherwise the first data segment
  becomes offset 0. Missing segments become NUL runs, so a hole is visible rather than silent.
- `dns.csv` is one row per DNS message (frame, query/response, name, qtype, answers). Sort it
  and the long base32 labels of DNS exfiltration jump out immediately.

## Extending it

- **More protocols**: add an `if 6667 in ports:` IRC branch (or 3306, MySQL) to `creds_from_stream`.
- **TLS**: this script only sees ciphertext. Decrypt first with the key log,
  `tshark -o tls.keylog_file:keys.log -r in.pcap -w out.pcap -F pcap`, then run it on `out.pcap`.
- **Carve everything, not just HTTP**: feed each file in `streams/` to `carve-and-identify`.

## Troubleshooting

- `ModuleNotFoundError: scapy` - the script exits 2 with the pip line. In a venv:
  `python3 -m venv v && ./v/bin/pip install scapy && ./v/bin/python pcap_extractor.py in.pcap`.
- Nothing extracted from a busy pcap: check the link type with `capinfos file.pcap`; scapy
  cannot dissect some exotic ones. Convert with `tshark -r in.pcapng -w out.pcap -F pcap`.
- Empty `dns.csv` but port 53 traffic exists: it is DNS-over-TCP. Read the stream from
  `streams/` and skip the two-byte length prefix before each message.
- Slow on a multi-GB capture: pre-filter with `tshark -r big.pcap -Y 'tcp.port==80' -w s.pcap`.
