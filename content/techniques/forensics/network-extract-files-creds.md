---
title: "PCAP - Extracting Files and Credentials from HTTP, FTP, SMB and SMTP"
category: forensics
subcategory: network
type: technique
tags: [pcap, tshark, wireshark, export-objects, http, ftp, telnet, smtp, smb, ntlmssp, netntlmv2, credentials, basic-auth, tcpflow, ngrep, networkminer, pcredz, scapy, hashcat, dfir]
difficulty: medium
summary: "Recover transferred files, plaintext logins and NTLM challenge/response pairs out of a capture, protocol by protocol."
when_to_use:
  - "The capture contains a file transfer and you need the file"
  - "The challenge asks for a username/password that crossed the wire"
  - "You see ftp, telnet, smtp, http or smb in the protocol hierarchy"
  - "NTLM authentication is present and you want a crackable hash"
tools: [tshark, wireshark, tcpflow, ngrep, networkminer, pcredz, scapy, hashcat, john, binwalk, foremost]
related: [network-pcap-triage, network-tls-decryption, network-c2-analysis, docs-email-forensics]
---

## TL;DR

Try `--export-objects` first; when the dissector fails, dump the raw TCP stream and carve. For
credentials the order is: `ngrep`/`PCredz` for the easy plaintext, then protocol-specific display
filters, then NTLMSSP field extraction for a `hashcat -m 5600` line.

## Recognise it

- Protocol hierarchy shows `http`, `ftp`, `ftp-data`, `telnet`, `smtp`, `imf`, `pop`, `imap`,
  `smb`/`smb2`, `tftp`, `nfs`.
- A single TCP conversation carrying hundreds of kilobytes with no TLS.
- `frame contains "Authorization: Basic"` or `frame contains "USER "` returns hits.
- `ntlmssp` appears in the protocol hierarchy -> a NetNTLM hash is in there.

## HTTP

```sh
# the easy path: every file the HTTP dissector reassembled
mkdir -p http_objs && tshark -r cap.pcap -q --export-objects http,http_objs
file http_objs/* && ls -la http_objs/
# list requests with their response codes and content lengths
tshark -r cap.pcap -Y http -T fields -e frame.number -e ip.src -e http.request.method \
  -e http.host -e http.request.uri -e http.response.code -e http.content_length
# only the responses that carried a body worth having
tshark -r cap.pcap -Y 'http.response && http.content_length > 1000' \
  -T fields -e frame.number -e http.content_type -e http.content_length
# raw body of one response, already de-chunked and de-gzipped by the dissector
tshark -r cap.pcap -Y 'frame.number == 452' -T fields -e http.file_data | tr -d ':\n' | xxd -r -p > body.bin
file body.bin
# uploads: multipart/form-data POST bodies
tshark -r cap.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data \
  | tr -d ':\n' | xxd -r -p > uploads.bin
strings uploads.bin | head -40
# basic auth, decoded
tshark -r cap.pcap -Y http.authorization -T fields -e http.authorization \
  | awk '{print $2}' | base64 -d
# cookies and session tokens
tshark -r cap.pcap -Y http.cookie -T fields -e http.host -e http.cookie | sort -u
# form-encoded credentials in a POST body
tshark -r cap.pcap -Y 'http.request.method == "POST"' -T fields -e urlencoded-form.key -e urlencoded-form.value
# when the dissector gave up: dump the stream raw and carve it
tshark -r cap.pcap -q -z follow,tcp,raw,7 | tail -n +7 | tr -d '\n' | xxd -r -p > stream7.bin
binwalk -e stream7.bin
foremost -t all -i stream7.bin -o carved7
```

Gzip and chunked encoding: Wireshark un-gzips automatically when
*Preferences > Protocols > HTTP > Uncompress entity bodies* is on (it is by default). From the
CLI that is `-o http.decompress_body:TRUE`. If you carve raw bytes yourself you must do it:

```sh
# a gzip body carved by hand still starts with 1f 8b
python3 -c "import gzip,sys;sys.stdout.buffer.write(gzip.decompress(open('body.bin','rb').read()))" > body.txt
```

## FTP

```sh
# the control channel: usernames and passwords in the clear
tshark -r cap.pcap -Y 'ftp.request.command in {"USER","PASS","ACCT"}' \
  -T fields -e frame.number -e ip.src -e ftp.request.command -e ftp.request.arg
# everything the client asked for
tshark -r cap.pcap -Y ftp.request -T fields -e ftp.request.command -e ftp.request.arg
# server responses (230 = login ok, 530 = failed)
tshark -r cap.pcap -Y ftp.response -T fields -e ftp.response.code -e ftp.response.arg
# data channel: RETR/STOR content rides on a SEPARATE tcp stream
tshark -r cap.pcap -q --export-objects ftp-data,ftp_objs
# manual extraction of the data channel
tshark -r cap.pcap -Y ftp-data -T fields -e data.data | tr -d ':\n' | xxd -r -p > transferred.bin
file transferred.bin
# passive mode: the 227 response tells you the data port -> (h1,h2,h3,h4,p1,p2), port = p1*256+p2
tshark -r cap.pcap -Y 'ftp.response.code == 227' -T fields -e ftp.response.arg
# active mode: the PORT command does the same from the client side
tshark -r cap.pcap -Y 'ftp.request.command == "PORT"' -T fields -e ftp.request.arg
```

## Telnet

Telnet echoes each typed character back, so the password appears one byte per packet in the
client->server direction and (usually) NOT echoed back for password prompts.

```sh
# everything that crossed a telnet session, rendered as text
tshark -r cap.pcap -q -z follow,tcp,ascii,0
# just the client's keystrokes, in order
tshark -r cap.pcap -Y 'telnet && ip.src == 10.0.0.5' -T fields -e telnet.data | tr -d '\n'
# a cleaner reassembly
tcpflow -r cap.pcap -o flows/ && cat flows/*23*  # port 23 files
# ngrep renders it line by line
ngrep -I cap.pcap -q -W byline '' 'tcp port 23'
```

## SMTP / IMAP / POP3

```sh
# complete email messages, headers and all
mkdir -p mail && tshark -r cap.pcap -q --export-objects imf,mail
ls mail/ && head -30 mail/*
# the SMTP conversation itself
tshark -r cap.pcap -Y smtp -T fields -e frame.number -e smtp.req.command -e smtp.req.parameter
# AUTH LOGIN sends username and password as two separate base64 lines
tshark -r cap.pcap -Y 'smtp.req.parameter' -T fields -e smtp.req.parameter \
  | grep -E '^[A-Za-z0-9+/=]{4,}$' | base64 -d
# AUTH PLAIN packs \0user\0pass into one base64 blob
tshark -r cap.pcap -Y 'smtp.auth.username || smtp.auth.password' \
  -T fields -e smtp.auth.username -e smtp.auth.password
# message bodies as reassembled fragments
tshark -r cap.pcap -Y smtp.data.fragment -T fields -e smtp.data.fragment | tr -d ':\n' | xxd -r -p
# POP3 and IMAP plaintext logins
tshark -r cap.pcap -Y 'pop.request.command in {"USER","PASS"}' -T fields -e pop.request.parameter
tshark -r cap.pcap -Y 'imap.request' -T fields -e imap.request | grep -i login
# base64 MIME attachments out of an exported .eml
python3 - <<'PY'
import email, sys, pathlib
msg = email.message_from_bytes(pathlib.Path("mail/message.eml").read_bytes())
for part in msg.walk():
    fn = part.get_filename()
    if fn:
        pathlib.Path(fn).write_bytes(part.get_payload(decode=True) or b"")
        print("wrote", fn)
PY
```

## SMB / SMB2

```sh
# files read or written over SMB
mkdir -p smb_objs && tshark -r cap.pcap -q --export-objects smb,smb_objs
tshark -r cap.pcap -q --export-objects smb2,smb_objs   # some builds split these
# every filename touched
tshark -r cap.pcap -Y smb2 -T fields -e smb2.filename | sort -u
tshark -r cap.pcap -Y smb  -T fields -e smb.file | sort -u
# tree connects show which shares were used - ADMIN$ / IPC$ / C$ mean lateral movement
tshark -r cap.pcap -Y 'smb2.cmd == 3' -T fields -e smb2.tree
# named pipes: \svcctl = service control (psexec), \atsvc = scheduled task, \srvsvc = enumeration
tshark -r cap.pcap -Y 'smb2.filename contains "svcctl" || smb.file contains "svcctl"'
# NTLMSSP: the three messages are NEGOTIATE(1), CHALLENGE(2), AUTH(3)
tshark -r cap.pcap -Y ntlmssp -T fields -e frame.number -e ntlmssp.messagetype \
  -e ntlmssp.auth.domain -e ntlmssp.auth.username -e ntlmssp.auth.hostname
# the pieces you need for a NetNTLMv2 hash
tshark -r cap.pcap -Y 'ntlmssp.messagetype == 0x00000002' -T fields -e ntlmssp.ntlmserverchallenge
tshark -r cap.pcap -Y 'ntlmssp.messagetype == 0x00000003' -T fields \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmv2_response
```

Assembling a NetNTLMv2 line for hashcat. The format is:

```
USER::DOMAIN:SERVERCHALLENGE:NTPROOFSTRING:BLOB
```

where `ntlmssp.ntlmv2_response` is `NTPROOFSTRING (first 16 bytes) || BLOB (the rest)`.

```sh
# pull the three fields and build the line
U=$(tshark -r cap.pcap -Y 'ntlmssp.messagetype == 0x00000003' -T fields -e ntlmssp.auth.username | head -1)
D=$(tshark -r cap.pcap -Y 'ntlmssp.messagetype == 0x00000003' -T fields -e ntlmssp.auth.domain | head -1)
C=$(tshark -r cap.pcap -Y 'ntlmssp.messagetype == 0x00000002' -T fields -e ntlmssp.ntlmserverchallenge | head -1 | tr -d ':')
R=$(tshark -r cap.pcap -Y 'ntlmssp.messagetype == 0x00000003' -T fields -e ntlmssp.ntlmv2_response | head -1 | tr -d ':')
printf '%s::%s:%s:%s:%s\n' "$U" "$D" "$C" "${R:0:32}" "${R:32}" > netntlmv2.txt
cat netntlmv2.txt
# crack it
hashcat -m 5600 netntlmv2.txt rockyou.txt
john --format=netntlmv2 --wordlist=rockyou.txt netntlmv2.txt
# NetNTLMv1 (short response, 48 hex chars) is -m 5500
hashcat -m 5500 netntlmv1.txt rockyou.txt
```

## Everything else

```sh
# TFTP: whole files, no auth at all
tshark -r cap.pcap -q --export-objects tftp,tftp_objs
tshark -r cap.pcap -Y tftp -T fields -e tftp.source_file -e tftp.destination_file
# HTTP/2 (needs TLS keys unless it is h2c cleartext)
tshark -r cap.pcap -Y 'http2.data.data' -T fields -e http2.data.data | tr -d ':\n' | xxd -r -p
tshark -r cap.pcap -Y http2.header -T fields -e http2.header.name -e http2.header.value
# MQTT
tshark -r cap.pcap -Y mqtt -T fields -e mqtt.topic -e mqtt.msg | head -40
tshark -r cap.pcap -Y 'mqtt.msgtype == 1' -T fields -e mqtt.username -e mqtt.passwd
# IRC (classic CTF C2)
tshark -r cap.pcap -Y irc -T fields -e irc.request -e irc.response
# LDAP simple bind sends the password in the clear
tshark -r cap.pcap -Y 'ldap.authentication == 0' -T fields -e ldap.name -e ldap.simple
# SNMP community strings
tshark -r cap.pcap -Y snmp -T fields -e snmp.community | sort -u
# NFS
tshark -r cap.pcap -Y nfs -T fields -e nfs.name | sort -u
# the shotgun: PCredz walks a pcap and prints every credential it can recognise
python3 Pcredz -f cap.pcap
# net-creds does the same job
python3 net-creds.py -p cap.pcap
# NetworkMiner extracts files, images, credentials and host inventory in one pass
mono NetworkMinerCLI.exe -r cap.pcap
# the lazy grep that catches surprisingly much
ngrep -I cap.pcap -q -W byline -i 'pass|pwd|login|user|token|api[-_]key'
strings -a cap.pcap | grep -aoiE '(password|passwd|pwd|token|api[_-]?key)[=: ][^ "&]{3,60}' | sort -u
```

## Code

```python
#!/usr/bin/env python3
"""Reassemble TCP streams from a pcap and scan them for credentials.

    pip install scapy
    python3 pcap_creds.py capture.pcap --outdir streams

Writes <outdir>/stream_<n>_c2s.bin and _s2c.bin for every TCP conversation, then
scans the reassembled bytes for HTTP basic auth, FTP USER/PASS, telnet input,
SMTP/IMAP/POP AUTH LOGIN base64 and generic key=value credential pairs.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import collections
import os
import re
import sys

try:
    from scapy.all import PcapReader, Raw  # type: ignore
    from scapy.layers.inet import IP, TCP  # type: ignore
except ImportError:  # pragma: no cover
    print("scapy is required:  pip install scapy", file=sys.stderr)
    raise SystemExit(1)

FlowKey = tuple[str, int, str, int]


def reassemble(pcap: str) -> dict[FlowKey, bytes]:
    """Return {(src, sport, dst, dport): payload} with segments ordered by sequence."""
    segs: dict[FlowKey, dict[int, bytes]] = collections.defaultdict(dict)
    with PcapReader(pcap) as reader:
        for pkt in reader:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            ip, tcp = pkt[IP], pkt[TCP]
            key: FlowKey = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
            data = bytes(pkt[Raw].load)
            if not data:
                continue
            seq = int(tcp.seq)
            # keep the longest segment seen at a given sequence (handles retransmits)
            if len(segs[key].get(seq, b"")) < len(data):
                segs[key][seq] = data
    out: dict[FlowKey, bytes] = {}
    for key, bucket in segs.items():
        buf = bytearray()
        expected: int | None = None
        for seq in sorted(bucket):
            data = bucket[seq]
            if expected is None:
                expected = seq
            if seq < expected:
                overlap = expected - seq
                if overlap >= len(data):
                    continue
                data = data[overlap:]
                seq = expected
            elif seq > expected:
                buf.extend(b"\x00" * min(seq - expected, 1 << 20))
            buf.extend(data)
            expected = seq + len(data)
        out[key] = bytes(buf)
    return out


PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("http-basic", re.compile(rb"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{4,})")),
    ("http-bearer", re.compile(rb"(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/-]{10,})")),
    ("http-digest", re.compile(rb"(?i)authorization:\s*digest\s+([^\r\n]{10,})")),
    ("ftp-user", re.compile(rb"(?i)^USER\s+([^\r\n]{1,64})", re.M)),
    ("ftp-pass", re.compile(rb"(?i)^PASS\s+([^\r\n]{1,64})", re.M)),
    ("pop-user", re.compile(rb"(?i)^USER\s+([^\r\n]{1,64})", re.M)),
    ("imap-login", re.compile(rb"(?i)^\S+\s+LOGIN\s+([^\r\n]{3,120})", re.M)),
    ("smtp-auth", re.compile(rb"(?i)^AUTH\s+(?:LOGIN|PLAIN)\s*([A-Za-z0-9+/=]*)", re.M)),
    ("form-creds", re.compile(rb"(?i)(?:user(?:name)?|login|email|pass(?:word|wd)?|pwd)"
                              rb"=([^&\r\n\s]{1,64})")),
    ("mysql-native", re.compile(rb"(?i)(mysql_native_password)")),
    ("cookie", re.compile(rb"(?i)^Cookie:\s*([^\r\n]{1,200})", re.M)),
    ("privkey", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]
B64_ONLY = re.compile(rb"^[A-Za-z0-9+/]{4,}={0,2}$")


def maybe_b64(blob: bytes) -> str | None:
    if not B64_ONLY.match(blob) or len(blob) % 4:
        return None
    try:
        dec = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    if all(32 <= c < 127 or c == 0 for c in dec):
        return dec.replace(b"\x00", b":").decode("latin-1")
    return None


def scan(label: str, data: bytes) -> None:
    for name, pat in PATTERNS:
        for m in pat.finditer(data):
            captured = m.group(1) if m.groups() else m.group(0)
            text = captured.decode("latin-1", "replace")
            decoded = maybe_b64(captured.strip())
            extra = f"   -> {decoded}" if decoded else ""
            print(f"  [{name}] {label}: {text[:200]}{extra}")


def standalone_b64_lines(label: str, data: bytes) -> None:
    """SMTP/IMAP AUTH LOGIN puts the username and password on their own base64 lines."""
    for line in data.split(b"\r\n"):
        line = line.strip()
        if 8 <= len(line) <= 200:
            dec = maybe_b64(line)
            if dec and any(ch.isalnum() for ch in dec):
                print(f"  [b64-line] {label}: {line.decode('latin-1')} -> {dec}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", nargs="?", default="capture.pcap")
    ap.add_argument("--outdir", default="streams")
    ap.add_argument("--min-size", type=int, default=1, help="skip streams smaller than this")
    ap.add_argument("--no-write", action="store_true", help="scan only, do not write files")
    args = ap.parse_args()

    try:
        flows = reassemble(args.pcap)
    except (FileNotFoundError, OSError) as exc:
        print(f"cannot read {args.pcap}: {exc}", file=sys.stderr)
        return 1

    if not args.no_write:
        os.makedirs(args.outdir, exist_ok=True)

    printed_header = False
    for idx, (key, data) in enumerate(sorted(flows.items(), key=lambda kv: -len(kv[1]))):
        if len(data) < args.min_size:
            continue
        src, sport, dst, dport = key
        label = f"{src}:{sport}->{dst}:{dport}"
        if not args.no_write:
            name = f"stream_{idx:04d}_{src}_{sport}_{dst}_{dport}.bin".replace(":", "_")
            with open(os.path.join(args.outdir, name), "wb") as fh:
                fh.write(data)
        if not printed_header:
            print("== credential candidates ==")
            printed_header = True
        scan(label, data)
        if dport in (25, 110, 143, 587, 993, 995) or sport in (25, 110, 143, 587, 993, 995):
            standalone_b64_lines(label, data)

    print(f"\n[+] {len(flows)} unidirectional TCP streams"
          f"{'' if args.no_write else f', written to {args.outdir}/'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **`--export-objects http` silently drops** responses that lack a `Content-Length` and were not
  cleanly terminated, and anything the TCP reassembler could not complete. Always cross-check the
  object count against the number of 200 responses.
- FTP data lives on a **different stream** than the control channel. Exporting `ftp-data` objects
  needs Wireshark to have seen the PORT/PASV negotiation; if the capture starts mid-session it
  will show the data as plain `tcp` and you must carve.
- A **gap in the capture** (dropped packets) produces a corrupted carve. `tshark -q -z expert`
  will tell you about "previous segment not captured".
- SMB3 encrypts by default; `smb2.encrypted` frames cannot be exported without the session key.
  SMB2 signing does not prevent extraction, only tampering.
- NTLMSSP over HTTP, LDAP, MSSQL and RPC works the same way -- the `ntlmssp` filter catches all of
  them, not just SMB.
- `ntlmssp.ntlmv2_response` sometimes renders with colons; strip them before building the hash.
- Base64 credentials may be UTF-16LE inside (Windows). If the decode looks like `u.s.e.r`, strip
  the NUL bytes.
- Exported objects keep server-supplied filenames -- never execute them, and hash them first.

## Tools

`tshark`/`wireshark`, `tcpflow`, `ngrep`, `NetworkMiner`, `PCredz`, `net-creds`, `chaosreader`,
`scapy`, `hashcat`, `john`, `binwalk`, `foremost`, `zeek` (`files.log` + extract-all-files).

## References

- `tshark -G fields | grep '^F\tntlmssp'` lists every NTLMSSP field name in your build.
- `man tshark` documents `--export-objects` and the protocols it supports.
