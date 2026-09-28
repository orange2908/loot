---
title: "C2 and Malware Traffic - Beacons, Custom Protocols and Decoding"
category: forensics
subcategory: network
type: technique
tags: [c2, command-and-control, beacon, beaconing, jitter, malware-traffic, custom-protocol, xor, repeating-key-xor, hamming-distance, rc4, length-prefix, domain-fronting, ja3, zeek, tshark, yara, dfir]
difficulty: hard
summary: "Find the beacon in the noise, reverse a length-prefixed custom protocol, and peel off the XOR/base64/zlib layers to the plaintext tasking."
when_to_use:
  - "One internal host contacts one external address at a suspiciously regular interval"
  - "A TCP stream on a high port carries binary data no dissector understands"
  - "The challenge says 'the malware phoned home, what did it send?'"
  - "You must extract the second-stage payload from HTTP traffic"
tools: [tshark, wireshark, zeek, scapy, python3, yara, binwalk, capa, cyberchef]
related: [network-pcap-triage, network-extract-files-creds, network-tls-decryption, network-covert-channels, memory-injected-code]
---

## TL;DR

Beacons are **regular**: plot the inter-arrival times of one conversation and look for a tight
cluster. Custom protocols are usually **length-prefixed**: check whether the first 2 or 4 bytes of
a stream equal the number of bytes that follow. Then brute-force single-byte XOR, guess a
repeating-key length with Hamming distance, and try base64/zlib at every layer.

## Recognise it

- `-z conv,tcp` shows one conversation with a long duration, low byte count and many packets.
- The same external IP appears every N seconds for hours with almost identical packet sizes.
- HTTP requests to a bare IP with no `Referer`, an odd `User-Agent`, and a large `Cookie`.
- TLS to an IP whose certificate is self-signed or whose CN is random.
- A high port (4444, 8080, 8443, 50050, 1337) carrying binary with no dissector.
- DNS queries to one domain at a fixed cadence (see the covert-channels technique).

## Finding the beacon

```sh
# candidate conversations, sorted by packet count with a small byte total
tshark -r cap.pcap -q -z conv,tcp | sort -k4 -n | tail -30
# every connection attempt to one host, as epoch times
tshark -r cap.pcap -Y 'ip.dst == 203.0.113.9 && tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields -e frame.time_epoch > beacon_times.txt
# inter-arrival deltas
awk 'NR>1{printf "%.3f\n", $1-p} {p=$1}' beacon_times.txt | sort -n | uniq -c | sort -rn | head
# a histogram of the deltas rounded to whole seconds
awk 'NR>1{printf "%d\n", int($1-p+0.5)} {p=$1}' beacon_times.txt | sort -n | uniq -c
# request sizes: a beacon sends almost the same number of bytes each time
tshark -r cap.pcap -Y 'ip.dst == 203.0.113.9 && tcp.len > 0' -T fields -e tcp.len \
  | sort -n | uniq -c | sort -rn | head
# zeek gives you duration and byte ratios per connection in one table
zeek -r cap.pcap
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state \
  | awk '$5 > 60 && $6 < 5000' | head -30
# connections per hour to each destination
cat conn.log | zeek-cut ts id.resp_h | awk '{print int($1/3600), $2}' | sort | uniq -c | sort -rn | head
# HTTP beacons: same URI over and over
cat http.log | zeek-cut host uri method user_agent | sort | uniq -c | sort -rn | head -20
```

**Jitter** means the interval is randomised by a percentage. A beacon with 20% jitter on a 60
second sleep produces deltas spread over 48-72 s. The distribution is still far tighter than human
browsing, and the *mean* is the sleep value.

## Generic C2 shapes

| Shape | What it looks like in the capture |
| --- | --- |
| HTTP GET beacon | Fixed URI, metadata encoded in a long `Cookie` header, empty response body until there is tasking |
| HTTP POST result | Small GETs plus occasional large POSTs to a different URI |
| Malleable profile | Requests that mimic a CDN or analytics endpoint, with the real data in a header or a fake JSON field |
| HTTPS with fixed JA3 | Same JA3 to many IPs; SNI absent or nonsensical |
| DNS beacon | See `network-covert-channels` |
| Raw TCP | High port, length-prefixed binary frames, no protocol dissector |
| Reverse shell | One long-lived TCP stream with interleaved short lines both directions |
| Domain fronting | `Host:` header (or inner HTTP host) different from the TLS SNI |

```sh
# odd or absent user agents
tshark -r cap.pcap -Y http.request -T fields -e http.user_agent | sort | uniq -c | sort -rn
# very long cookies
tshark -r cap.pcap -Y http.cookie -T fields -e http.host -e http.cookie | awk 'length > 250'
# requests to a bare IP in the Host header
tshark -r cap.pcap -Y 'http.host matches "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"' \
  -T fields -e http.host -e http.request.uri
# Host vs SNI mismatch (domain fronting)
tshark -r cap.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u
tshark -r cap.pcap -Y http.host -T fields -e ip.dst -e http.host | sort -u
# self-signed certificates: subject == issuer
zeek -r cap.pcap && cat x509.log | zeek-cut certificate.subject certificate.issuer \
  | awk '$1 == $2' | sort -u
# repeated JA3 across many destinations
cat ssl.log | zeek-cut ja3 id.resp_h server_name | sort | uniq -c | sort -rn | head
# DNS answers with a TTL of 0 or 1 (fast flux / dynamic C2)
tshark -r cap.pcap -Y 'dns.resp.ttl < 5' -T fields -e dns.qry.name -e dns.resp.ttl | sort -u
```

## Reverse engineering a custom protocol

### 1. Get one full stream as raw bytes

```sh
# list the streams and pick the interesting index
tshark -r cap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e tcp.stream -e ip.dst -e tcp.dstport
# dump one stream as hex, both directions interleaved
tshark -r cap.pcap -q -z follow,tcp,hex,3
# raw bytes, both directions (the header lines need stripping)
tshark -r cap.pcap -q -z follow,tcp,raw,3 > stream3.txt
# only the client->server direction, as bytes
tshark -r cap.pcap -Y 'tcp.stream == 3 && ip.src == 10.0.0.5 && tcp.len > 0' \
  -T fields -e data.data | tr -d ':\n' | xxd -r -p > c2s.bin
# same for server->client
tshark -r cap.pcap -Y 'tcp.stream == 3 && ip.dst == 10.0.0.5 && tcp.len > 0' \
  -T fields -e data.data | tr -d ':\n' | xxd -r -p > s2c.bin
# or use tcpflow, which splits directions for you
tcpflow -r cap.pcap -o flows/
```

### 2. Look for structure

```sh
# first 64 bytes, annotated by eye
xxd -l 64 c2s.bin
# does the first 4 bytes little-endian equal the remaining length?
python3 -c "import struct;d=open('c2s.bin','rb').read();print(struct.unpack('<I',d[:4])[0], len(d)-4)"
# and big-endian
python3 -c "import struct;d=open('c2s.bin','rb').read();print(struct.unpack('>I',d[:4])[0], len(d)-4)"
# 2-byte prefix
python3 -c "import struct;d=open('c2s.bin','rb').read();print(struct.unpack('<H',d[:2])[0], struct.unpack('>H',d[:2])[0], len(d)-2)"
# byte-frequency histogram: a flat histogram means encryption or compression
python3 -c "import collections,sys;d=open('c2s.bin','rb').read();c=collections.Counter(d);print(c.most_common(10))"
# repeating bytes at a fixed stride reveal a repeating XOR key
xxd c2s.bin | head -20
# entropy: > 7.5 bits/byte means encrypted or compressed, ~4-5 means base64 of binary
python3 -c "import collections,math;d=open('c2s.bin','rb').read();c=collections.Counter(d);n=len(d);print(round(-sum(v/n*math.log2(v/n) for v in c.values()),2))"
```

Structural tells:

- A constant 4-8 byte prefix on every frame = a magic value.
- A counter that increments by 1 per frame = a sequence number.
- A field that is always 0x00-0x0f = a command opcode.
- A 16-byte block alignment = AES-CBC/ECB (the first 16 bytes may be the IV).
- Length that is always a multiple of 16 but the content is high entropy = block cipher.
- Base64 characters only = decode first, then analyse the bytes.

### 3. Peel the layers

```sh
# single-byte XOR brute force, looking for printable output
python3 - <<'PY'
d = open("c2s.bin","rb").read()
for k in range(256):
    out = bytes(b ^ k for b in d[:200])
    printable = sum(1 for c in out if 32 <= c < 127 or c in (9,10,13)) / len(out)
    if printable > 0.9:
        print(hex(k), out[:120])
PY
# known-plaintext XOR: if you expect "MZ" or "HTTP/1.1" at offset 0
python3 -c "d=open('c2s.bin','rb').read();print(bytes(a^b for a,b in zip(d[:8], b'HTTP/1.1')).hex())"
# base64 -> file
tr -d '\n' < blob.b64 | base64 -d > out.bin && file out.bin
# zlib / gzip after a header of N bytes
python3 -c "import zlib,sys;d=open('c2s.bin','rb').read();sys.stdout.buffer.write(zlib.decompress(d[8:]))"
python3 -c "import gzip,sys;d=open('c2s.bin','rb').read();sys.stdout.buffer.write(gzip.decompress(d[4:]))"
# RC4 with a guessed key
python3 - <<'PY'
def rc4(key, data):
    S = list(range(256)); j = 0; out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for c in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) % 256])
    return bytes(out)
print(rc4(b"secret", open("c2s.bin","rb").read())[:200])
PY
```

### 4. Extract the staged payload

```sh
# a PE in an HTTP response
mkdir objs && tshark -r cap.pcap -q --export-objects http,objs
file objs/* | grep -i 'PE32\|ELF\|Mach-O'
# a PE that is XOR'd or prefixed - binwalk finds the MZ anywhere
binwalk -e objs/download.bin
grep -abo 'MZ' objs/download.bin | head
grep -abo 'This program cannot' objs/download.bin | head
# verify it is a real PE (MZ at 0, e_lfanew points at 'PE\0\0')
python3 -c "import struct;d=open('stage2.bin','rb').read();o=struct.unpack_from('<I',d,0x3c)[0];print(d[:2], d[o:o+4])"
# triage the payload
capa stage2.bin
yara -r rules/ stage2.bin
strings -a -el stage2.bin | grep -iE '(http|\.onion|cmd|powershell|user-agent)'
```

## Code

```python
#!/usr/bin/env python3
"""Reverse a length-prefixed custom protocol stream and peel XOR/base64/zlib layers.

Reads a raw one-direction TCP stream dump (see the tshark recipes above), detects
the framing, splits the frames, and tries several decodings on each, printing any
that becomes mostly printable.

    python3 c2_decode.py c2s.bin
    python3 c2_decode.py c2s.bin --prefix 4le --skip-header 8
    python3 c2_decode.py --selftest
"""
from __future__ import annotations

import argparse
import base64
import binascii
import collections
import math
import struct
import sys
import zlib

PREFIX_FORMATS = {"4le": ("<I", 4), "4be": (">I", 4), "2le": ("<H", 2), "2be": (">H", 2)}
# try the wider prefixes first: a 4-byte LE length also parses as a 2-byte LE
# length followed by two zero bytes, and the wider reading is the natural one
PREFIX_ORDER = ("4le", "4be", "2le", "2be")


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for c in data if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(data)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_prefix(data: bytes, max_frames: int = 8) -> tuple[str, int] | None:
    """Return (format_name, header_extra) if a length prefix parses the whole stream."""
    for name in PREFIX_ORDER:
        fmt, size = PREFIX_FORMATS[name]
        for extra in (0, 1, 2, 4, 8, 12, 16):
            off = 0
            frames = 0
            ok = True
            while off + size + extra <= len(data) and frames < max_frames * 4:
                try:
                    length = struct.unpack_from(fmt, data, off)[0]
                except struct.error:
                    ok = False
                    break
                body = off + size + extra
                if length == 0 or body + length > len(data):
                    ok = body == len(data)
                    break
                off = body + length
                frames += 1
            if ok and frames >= 2 and off == len(data):
                return name, extra
    return None


def split_frames(data: bytes, name: str, extra: int) -> list[bytes]:
    fmt, size = PREFIX_FORMATS[name]
    frames: list[bytes] = []
    off = 0
    while off + size + extra <= len(data):
        length = struct.unpack_from(fmt, data, off)[0]
        body = off + size + extra
        if length == 0 or body + length > len(data):
            break
        frames.append(data[body:body + length])
        off = body + length
    return frames


def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_key_length(data: bytes, lo: int = 2, hi: int = 16) -> list[tuple[int, float]]:
    """Rank candidate repeating-XOR key lengths by mean normalised Hamming distance."""
    scores: list[tuple[int, float]] = []
    for klen in range(lo, min(hi, max(lo, len(data) // 4)) + 1):
        blocks = [data[i * klen:(i + 1) * klen] for i in range(len(data) // klen)]
        blocks = [b for b in blocks if len(b) == klen][:12]
        if len(blocks) < 2:
            continue
        pairs = [(blocks[i], blocks[i + 1]) for i in range(len(blocks) - 1)]
        dist = sum(hamming(a, b) for a, b in pairs) / (len(pairs) * klen)
        scores.append((klen, round(dist, 4)))
    scores.sort(key=lambda kv: kv[1])
    return scores


def best_single_byte(block: bytes) -> tuple[int, float]:
    best = (0, -1.0)
    for k in range(256):
        out = bytes(b ^ k for b in block)
        score = printable_ratio(out)
        # prefer keys that produce letters and spaces, not just any printable byte
        score += sum(1 for c in out if c in b" etaoinshrdlu") / (len(out) * 4)
        if score > best[1]:
            best = (k, score)
    return best


def recover_repeating_key(data: bytes, klen: int) -> bytes:
    key = bytearray()
    for i in range(klen):
        column = data[i::klen]
        key.append(best_single_byte(column)[0])
    return bytes(key)


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def attempts(frame: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = [("raw", frame)]

    # XORing printable ASCII with a small constant often stays printable, so rank
    # every candidate and keep the best few rather than stopping at the first hit
    ranked_keys: list[tuple[float, int, bytes]] = []
    for k in range(1, 256):
        cand = bytes(b ^ k for b in frame)
        ratio = printable_ratio(cand)
        if ratio < 0.9:
            continue
        common = sum(1 for c in cand if c in b" etaoinshrdlu\"{}:,")
        ranked_keys.append((ratio + common / max(1, len(cand)), k, cand))
    ranked_keys.sort(key=lambda t: -t[0])
    for _, k, cand in ranked_keys[:4]:
        out.append((f"xor-1byte:0x{k:02x}", cand))

    if len(frame) >= 16:
        for klen, _ in guess_key_length(frame)[:3]:
            key = recover_repeating_key(frame, klen)
            cand = xor(frame, key)
            if printable_ratio(cand) > 0.9:
                out.append((f"xor-key:{key.hex()}", cand))
                break

    stripped = bytes(c for c in frame if c not in b"\r\n")
    if stripped and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                        for c in stripped):
        try:
            out.append(("base64", base64.b64decode(stripped + b"=" * (-len(stripped) % 4))))
        except (binascii.Error, ValueError):
            pass

    for skip in (0, 2, 4, 8):
        chunk = frame[skip:]
        if len(chunk) < 4:
            continue
        try:
            out.append((f"zlib+{skip}", zlib.decompress(chunk)))
            break
        except zlib.error:
            pass
        try:
            out.append((f"gzip+{skip}", zlib.decompress(chunk, 16 + zlib.MAX_WBITS)))
            break
        except zlib.error:
            pass
    return out


def report(frames: list[bytes], limit: int) -> None:
    for i, frame in enumerate(frames[:limit]):
        print(f"\n-- frame {i}  {len(frame)} bytes  entropy={entropy(frame):.2f}")
        print(f"   hex: {frame[:32].hex()}")
        for name, cand in attempts(frame):
            ratio = printable_ratio(cand)
            if name != "raw" and ratio < 0.8:
                continue
            preview = "".join(chr(c) if 32 <= c < 127 else "." for c in cand[:140])
            print(f"   {name:<22} printable={ratio:.2f}  {preview}")


def selftest() -> int:
    plaintext_frames = [
        b'{"cmd":"sleep","interval":60}',
        b'{"cmd":"exec","args":"whoami"}',
        b'{"result":"CORP\\\\alice","flag":"flag{c2_decoded}"}',
    ]
    key = b"\x13\x37\xbe\xef"
    blob = bytearray()
    for frame in plaintext_frames:
        enc = xor(frame, key)
        blob += struct.pack("<I", len(enc)) + enc
    data = bytes(blob)

    detected = detect_prefix(data)
    assert detected == ("4le", 0), detected
    frames = split_frames(data, *detected)
    assert len(frames) == 3, len(frames)
    assert len(frames[0]) == len(plaintext_frames[0])

    # decrypting with the known key must give the plaintext back
    recovered = xor(frames[2], key)
    assert b"flag{c2_decoded}" in recovered, recovered

    # key-length guessing needs a decent amount of ciphertext to be reliable
    long_cipher = xor(b" ".join(plaintext_frames) * 8, key)
    ranked = guess_key_length(long_cipher)
    assert ranked[0][0] % 4 == 0, ranked[:4]
    guessed = recover_repeating_key(long_cipher, 4)
    assert guessed == key, (guessed.hex(), key.hex())
    assert b"flag{c2_decoded}" in xor(long_cipher, guessed)

    # single-byte XOR must be found end to end
    single = bytes(b ^ 0x5A for b in plaintext_frames[2])
    assert any(b"flag{c2_decoded}" in cand for _, cand in attempts(single)), "1-byte xor missed"

    assert entropy(b"\x00" * 100) == 0.0
    assert printable_ratio(b"hello") == 1.0
    assert hamming(b"this is a test", b"wokka wokka!!!") == 37
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("stream", nargs="?", help="raw one-direction TCP stream dump")
    ap.add_argument("--prefix", choices=sorted(PREFIX_FORMATS),
                    help="force the length-prefix format instead of detecting it")
    ap.add_argument("--skip-header", type=int, default=0,
                    help="extra header bytes between the length and the body")
    ap.add_argument("--limit", type=int, default=12, help="frames to report")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.stream:
        return selftest()

    try:
        with open(args.stream, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        print(f"no such file: {args.stream}", file=sys.stderr)
        return 1

    print(f"== {len(data)} bytes, entropy {entropy(data):.2f} bits/byte")
    if entropy(data) > 7.5:
        print("   high entropy: encrypted or compressed, not a plain encoding")

    if args.prefix:
        kind: tuple[str, int] | None = (args.prefix, args.skip_header)
    else:
        kind = detect_prefix(data)

    if kind:
        print(f"== length prefix detected: {kind[0]} with {kind[1]} extra header bytes")
        frames = split_frames(data, *kind)
        print(f"   {len(frames)} frames, sizes {[len(f) for f in frames[:12]]}")
    else:
        print("== no length prefix found; treating the whole stream as one frame")
        frames = [data]

    report(frames, args.limit)

    if len(frames) > 1:
        sizes = collections.Counter(len(f) for f in frames)
        print(f"\n== frame size histogram: {sizes.most_common(8)}")
    print("\n== key-length candidates (repeating XOR, lower is better)")
    for klen, dist in guess_key_length(data)[:6]:
        print(f"   {klen:>3}  {dist}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```yara
rule generic_c2_indicators
{
    meta:
        description = "Strings commonly present in extracted C2 payloads and stagers"
        author = "ctf-brain"
    strings:
        $ua1 = "Mozilla/4.0 (compatible; MSIE" ascii wide
        $ua2 = "User-Agent:" ascii wide
        $wininet1 = "InternetOpenA" ascii
        $wininet2 = "InternetConnectA" ascii
        $wininet3 = "HttpSendRequestA" ascii
        $ws1 = "WSASocketA" ascii
        $ws2 = "WSAStartup" ascii
        $proc1 = "CreateProcessA" ascii
        $proc2 = "cmd.exe /c" ascii wide
        $proc3 = "powershell" ascii wide nocase
        $stager = { fc 48 83 e4 f0 e8 }
        $mz = "MZ"
        $dos = "This program cannot be run in DOS mode"
    condition:
        ($mz at 0 and $dos and 2 of ($wininet*, $ws*, $proc*))
        or $stager
        or (3 of ($ua*, $wininet*, $proc*))
}
```

## Variants & pitfalls

- **A regular interval is not proof of malice.** NTP, monitoring agents, software update checks,
  DNS refreshes and telemetry all beacon. Corroborate with the destination, the process (from a
  memory image) and the payload.
- **Sleep + jitter hides the mean** if you only look at raw deltas. Bin them and look at the
  distribution, not at individual values.
- **A single long-lived TCP connection** (interactive shell, SOCKS proxy) has no beacon pattern
  at all. Look for duration and a low byte count instead.
- Length-prefix detection fails if the capture **starts mid-stream**. Slide the start offset by
  1..32 bytes and retry.
- High entropy after every decoding attempt means **real crypto**. Move to the binary: find the
  key in the malware sample, or in the memory image.
- `--export-objects http` **will not** give you a payload that was chunked and XOR'd. Carve the
  raw stream instead.
- Beware **false plaintext**: a single-byte XOR that yields 90% printable bytes on a 20-byte
  sample is often luck. Verify on a longer frame.
- **Never resolve or connect to** the C2 indicators you extract from a CTF capture.

## Tools

`tshark`/`wireshark`, `zeek` (conn.log, http.log, ssl.log, x509.log), `tcpflow`, `scapy`,
`python3`, `yara`, `capa`, `binwalk`, `CyberChef` (offline build), `RITA` (beacon scoring),
`hashcat` when a key turns out to be a password.

## References

- `tshark -q -z follow,tcp,raw,N` is documented in `man tshark` under the `follow` tap.
- Zeek's `conn.log` field meanings (`conn_state`, `orig_bytes`, `resp_bytes`) are in the Zeek
  documentation shipped with the distribution.
