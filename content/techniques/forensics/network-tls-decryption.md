---
title: "PCAP - Decrypting TLS and What You Learn Without Keys"
category: forensics
subcategory: network
type: technique
tags: [tls, ssl, pcap, tshark, wireshark, sslkeylogfile, keylog, client-random, rsa-private-key, ja3, ja3s, ja4, sni, x509, certificate, http2, quic, editcap, zeek, dfir]
difficulty: medium
summary: "Use an SSLKEYLOGFILE or an RSA key to read encrypted traffic, and extract SNI, certificates and JA3 fingerprints when you have neither."
when_to_use:
  - "The capture is mostly TLS and the interesting protocol is inside it"
  - "A keylog file, .key/.pem, or a .pcapng with embedded secrets came with the challenge"
  - "You need to identify a C2 server or a client application from encrypted traffic"
  - "You must prove which hostnames were visited without decrypting anything"
tools: [tshark, wireshark, editcap, openssl, zeek, scapy, python3]
related: [network-pcap-triage, network-extract-files-creds, network-c2-analysis, network-covert-channels]
---

## TL;DR

If you have a **keylog file**, `-o tls.keylog_file:keys.log` decrypts everything including TLS 1.3.
If you only have an **RSA private key**, it works only for non-forward-secret `TLS_RSA_WITH_*`
suites. With neither, you can still read the SNI, the server certificate, the ALPN, and compute
a JA3 fingerprint -- which is often all the flag needs.

## Recognise it

- Protocol hierarchy dominated by `tls`, `tcp` with port 443, or `quic`/`udp` 443.
- Files shipped with the challenge named `sslkeylog.txt`, `keys.log`, `premaster.txt`,
  `*.key`, `*.pem`, `server.pfx`.
- A `.pcapng` whose `capinfos` mentions Decryption Secrets Blocks, or which decrypts in Wireshark
  with no configuration at all.
- `tls.handshake.type == 1` frames present -> full handshakes were captured (you need these;
  a resumed session with a cached ticket cannot be decrypted from a keylog CLIENT_RANDOM alone
  unless that session's secrets are also in the file).

## Route 1 - the keylog file (works for TLS 1.0 through 1.3)

The NSS key log format is one secret per line, whitespace-separated:

```
CLIENT_RANDOM <64 hex chars of client random> <96 hex chars master secret>
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client random> <secret>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client random> <secret>
CLIENT_TRAFFIC_SECRET_0 <client random> <secret>
SERVER_TRAFFIC_SECRET_0 <client random> <secret>
EXPORTER_SECRET <client random> <secret>
RSA <8 bytes of encrypted premaster> <premaster secret>
```

`CLIENT_RANDOM` alone is enough for TLS 1.2 and below. TLS 1.3 needs the four
`*_TRAFFIC_SECRET*` lines; a file with only `CLIENT_RANDOM` will not decrypt a 1.3 session.

```sh
# how the capture side produces one (browsers and anything using NSS/OpenSSL via curl)
export SSLKEYLOGFILE=/tmp/keys.log && firefox &
export SSLKEYLOGFILE=/tmp/keys.log && google-chrome --user-data-dir=/tmp/p &
curl --ssl-no-revoke -o /dev/null https://example.com   # honours SSLKEYLOGFILE in recent builds
# decrypt on the CLI
tshark -r cap.pcapng -o tls.keylog_file:/tmp/keys.log -Y http
# and pull the decrypted HTTP/2 payloads out
tshark -r cap.pcapng -o tls.keylog_file:/tmp/keys.log -Y http2.data.data \
  -T fields -e http2.data.data | tr -d ':\n' | xxd -r -p
# HTTP/1.1 inside TLS after decryption
tshark -r cap.pcapng -o tls.keylog_file:/tmp/keys.log -Y http.request \
  -T fields -e http.host -e http.request.uri
# export objects out of decrypted traffic, same as cleartext
mkdir objs && tshark -r cap.pcapng -o tls.keylog_file:/tmp/keys.log -q --export-objects http,objs
# see the decrypted application data as a stream
tshark -r cap.pcapng -o tls.keylog_file:/tmp/keys.log -q -z follow,tls,ascii,0
# bake the secrets INTO the pcapng so the file decrypts anywhere
editcap --inject-secrets tls,/tmp/keys.log cap.pcap cap_with_secrets.pcapng
# confirm the block landed
capinfos cap_with_secrets.pcapng | grep -i secret
```

In the GUI: *Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename*.

Wireshark 3.x and earlier used the preference name `ssl.keylog_file`; 4.x uses `tls.keylog_file`.
If `-o tls.keylog_file:` errors, try the `ssl.` form.

## Route 2 - the RSA private key (TLS 1.2 and earlier, non-PFS only)

This works **only** when the key exchange was plain RSA, i.e. the negotiated cipher suite name
starts `TLS_RSA_WITH_`. Any `ECDHE`/`DHE` suite has forward secrecy and the private key is useless.

```sh
# first: is it even possible? read the negotiated suite from the ServerHello
tshark -r cap.pcap -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.ciphersuite
# and the client's offer list from the ClientHello
tshark -r cap.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.ciphersuite
# 0x002f TLS_RSA_WITH_AES_128_CBC_SHA, 0x0035 AES_256_CBC_SHA, 0x009c AES_128_GCM_SHA256 -> decryptable
# anything 0xc0xx / 0x13xx with ECDHE -> not decryptable with the private key
# decrypt with the key
tshark -r cap.pcap -o "uat:rsa_keys:\"/path/server.key\",\"\"" -Y http
# older Wireshark syntax with the explicit ip,port,protocol,keyfile,password tuple
tshark -r cap.pcap -o "ssl.keys_list:10.0.0.10,443,http,/path/server.key" -Y http
# if the key is in a PKCS#12 bundle, split it first
openssl pkcs12 -in server.pfx -nocerts -nodes -out server.key
openssl pkcs12 -in server.pfx -clcerts -nokeys -out server.crt
# verify the key matches the certificate you see in the capture
openssl rsa  -in server.key -noout -modulus | openssl md5
openssl x509 -in server.crt -noout -modulus | openssl md5
```

GUI: *Preferences > Protocols > TLS > RSA keys list > Edit*.

## Route 3 - what you can learn with no keys at all

```sh
# SNI: the hostname the client asked for, in the clear inside the ClientHello
tshark -r cap.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e frame.number -e ip.dst -e tls.handshake.extensions_server_name | sort -u
# ALPN: h2, http/1.1, or something exotic like a custom protocol id
tshark -r cap.pcap -Y tls.handshake.type==1 -T fields -e tls.handshake.extensions_alpn_str
# supported versions / groups - fingerprints the client stack
tshark -r cap.pcap -Y tls.handshake.type==1 \
  -T fields -e tls.handshake.extensions_supported_version -e tls.handshake.extensions_supported_group
# the server certificate chain, as DER hex
tshark -r cap.pcap -Y 'tls.handshake.certificate' -T fields -e tls.handshake.certificate \
  | head -1 | tr -d ':\n' | xxd -r -p > server.der
openssl x509 -inform DER -in server.der -noout -text
openssl x509 -inform DER -in server.der -noout -subject -issuer -dates -fingerprint -sha256
# subject alternative names - the real pivot
openssl x509 -inform DER -in server.der -noout -ext subjectAltName
# self-signed? subject == issuer
openssl x509 -inform DER -in server.der -noout -subject -issuer
# certificate fields Wireshark already parsed for you
tshark -r cap.pcap -Y tls.handshake.certificate \
  -T fields -e x509sat.printableString -e x509ce.dNSName | sort -u
# record sizes and direction over time - traffic analysis without decryption
tshark -r cap.pcap -Y 'tls.record.content_type == 23' \
  -T fields -e frame.time_epoch -e ip.src -e tls.record.length
# zeek gives you all of this as structured logs including ja3/ja3s
zeek -r cap.pcap && cat ssl.log | zeek-cut ts server_name ja3 ja3s version cipher subject issuer
cat x509.log | zeek-cut certificate.subject certificate.issuer san.dns
```

### JA3 / JA3S / JA4

JA3 fingerprints the **client** from fields that are visible in the cleartext ClientHello. The
string is five comma-separated parts, then MD5 of that string:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
```

- `SSLVersion` is the ClientHello's `legacy_version` as a decimal number (771 = 0x0303).
- `Ciphers`, `Extensions`, `EllipticCurves` are dash-separated decimal lists **in wire order**.
- GREASE values (0x0a0a, 0x1a1a, ... any `0x?a?a` where both bytes match the pattern) are removed.
- Empty lists render as an empty field, so `771,4865-4866,,,` is valid.

JA3S does the same for the ServerHello: `SSLVersion,Cipher,Extensions`.
JA4 is a newer, structured scheme (`t13d1516h2_8daaf6152771_02713d6af862`-style) that encodes
protocol, version, SNI presence, counts, ALPN and sorted hashes; Wireshark 4.2+ and zeek plugins
emit it directly as `tls.handshake.ja4`.

```sh
# if your tshark has the ja3 fields built in
tshark -r cap.pcap -Y tls.handshake.type==1 -T fields -e tls.handshake.ja3 -e tls.handshake.ja3_full
tshark -r cap.pcap -Y tls.handshake.type==2 -T fields -e tls.handshake.ja3s
tshark -r cap.pcap -Y tls.handshake.type==1 -T fields -e tls.handshake.ja4
```

## Code

```python
#!/usr/bin/env python3
"""Parse TLS ClientHello records straight out of a pcap and compute a JA3 fingerprint.

Does the TLS parsing on raw bytes, so it works with any scapy build and does not
need scapy's optional TLS layer.

    pip install scapy
    python3 ja3_from_pcap.py capture.pcap
    python3 ja3_from_pcap.py --selftest
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a
EXT_EC_POINT_FORMATS = 0x000b
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002b
VERSION_NAMES = {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
                 0x0303: "TLS1.2", 0x0304: "TLS1.3"}


class ParseError(Exception):
    pass


def u8(b: bytes, o: int) -> int:
    if o + 1 > len(b):
        raise ParseError("short read u8")
    return b[o]


def u16(b: bytes, o: int) -> int:
    if o + 2 > len(b):
        raise ParseError("short read u16")
    return struct.unpack_from(">H", b, o)[0]


def u24(b: bytes, o: int) -> int:
    if o + 3 > len(b):
        raise ParseError("short read u24")
    return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]


def parse_client_hello(rec: bytes) -> dict[str, object]:
    """rec is one TLS record payload starting at the handshake header (0x01 ...)."""
    if u8(rec, 0) != 0x01:
        raise ParseError("not a ClientHello")
    body_len = u24(rec, 1)
    body = rec[4:4 + body_len]
    if len(body) < body_len:
        raise ParseError("truncated ClientHello")
    off = 0
    legacy_version = u16(body, off)
    off += 2
    off += 32                                  # random
    sid_len = u8(body, off)
    off += 1 + sid_len
    cs_len = u16(body, off)
    off += 2
    ciphers = [u16(body, off + i) for i in range(0, cs_len, 2)]
    off += cs_len
    comp_len = u8(body, off)
    off += 1 + comp_len

    exts: list[int] = []
    groups: list[int] = []
    formats: list[int] = []
    sni = ""
    alpn: list[str] = []
    negotiated = legacy_version

    if off + 2 <= len(body):
        ext_total = u16(body, off)
        off += 2
        end = min(len(body), off + ext_total)
        while off + 4 <= end:
            etype = u16(body, off)
            elen = u16(body, off + 2)
            edata = body[off + 4:off + 4 + elen]
            off += 4 + elen
            exts.append(etype)
            if etype == EXT_SERVER_NAME and len(edata) >= 5:
                # list_len(2) | name_type(1) | name_len(2) | name
                name_len = u16(edata, 3)
                sni = edata[5:5 + name_len].decode("latin-1", "replace")
            elif etype == EXT_SUPPORTED_GROUPS and len(edata) >= 2:
                glen = u16(edata, 0)
                groups = [u16(edata, 2 + i) for i in range(0, glen, 2)]
            elif etype == EXT_EC_POINT_FORMATS and len(edata) >= 1:
                flen = edata[0]
                formats = list(edata[1:1 + flen])
            elif etype == EXT_ALPN and len(edata) >= 2:
                p = 2
                while p < len(edata):
                    ln = edata[p]
                    alpn.append(edata[p + 1:p + 1 + ln].decode("latin-1", "replace"))
                    p += 1 + ln
            elif etype == EXT_SUPPORTED_VERSIONS and len(edata) >= 1:
                vlen = edata[0]
                offered = [u16(edata, 1 + i) for i in range(0, vlen, 2)]
                offered = [v for v in offered if v not in GREASE]
                if offered:
                    negotiated = max(offered)

    def clean(xs: list[int]) -> list[int]:
        return [x for x in xs if x not in GREASE]

    ja3 = "{},{},{},{},{}".format(
        legacy_version,
        "-".join(str(c) for c in clean(ciphers)),
        "-".join(str(e) for e in clean(exts)),
        "-".join(str(g) for g in clean(groups)),
        "-".join(str(f) for f in formats),
    )
    return {
        "legacy_version": legacy_version,
        "version": VERSION_NAMES.get(negotiated, hex(negotiated)),
        "sni": sni,
        "alpn": alpn,
        "ciphers": clean(ciphers),
        "extensions": clean(exts),
        "groups": clean(groups),
        "ja3": ja3,
        "ja3_md5": hashlib.md5(ja3.encode()).hexdigest(),
    }


def iter_handshake_records(payload: bytes):
    """Yield handshake-record payloads (content type 22) from a TCP payload."""
    off = 0
    while off + 5 <= len(payload):
        ctype = payload[off]
        version = u16(payload, off + 1)
        length = u16(payload, off + 3)
        if ctype != 22 or not (0x0300 <= version <= 0x0304) or length == 0:
            return
        yield payload[off + 5:off + 5 + length]
        off += 5 + length


def build_sample_client_hello() -> bytes:
    """Construct a minimal but well-formed ClientHello record for the self-test."""
    ciphers = [0x1301, 0x1302, 0xc02b]
    host = b"ctf.example.org"
    # ext_type | ext_len | list_len | name_type | name_len | name
    inner = b"\x00" + struct.pack(">H", len(host)) + host
    sni_body = struct.pack(">H", len(inner)) + inner
    sni_ext = struct.pack(">HH", EXT_SERVER_NAME, len(sni_body)) + sni_body
    groups_body = struct.pack(">H", 4) + struct.pack(">HH", 0x001d, 0x0017)
    groups_ext = struct.pack(">HH", EXT_SUPPORTED_GROUPS, len(groups_body)) + groups_body
    fmt_body = b"\x01\x00"
    fmt_ext = struct.pack(">HH", EXT_EC_POINT_FORMATS, len(fmt_body)) + fmt_body
    exts = sni_ext + groups_ext + fmt_ext
    body = (struct.pack(">H", 0x0303) + b"\xab" * 32 + b"\x00"
            + struct.pack(">H", len(ciphers) * 2)
            + b"".join(struct.pack(">H", c) for c in ciphers)
            + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def selftest() -> int:
    rec = build_sample_client_hello()
    payloads = list(iter_handshake_records(rec))
    assert len(payloads) == 1, payloads
    info = parse_client_hello(payloads[0])
    assert info["sni"] == "ctf.example.org", info["sni"]
    assert info["ciphers"] == [0x1301, 0x1302, 0xc02b], info["ciphers"]
    assert info["ja3"].startswith("771,4865-4866-49195,"), info["ja3"]
    assert len(str(info["ja3_md5"])) == 32
    print("self-test OK")
    print(f"  ja3      = {info['ja3']}")
    print(f"  ja3_md5  = {info['ja3_md5']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.pcap:
        return selftest()

    try:
        from scapy.all import PcapReader, Raw  # type: ignore
        from scapy.layers.inet import IP, TCP  # type: ignore
    except ImportError:
        print("scapy is required for pcap mode:  pip install scapy", file=sys.stderr)
        return 1

    seen: set[str] = set()
    with PcapReader(args.pcap) as reader:
        for pkt in reader:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            payload = bytes(pkt[Raw].load)
            if not payload.startswith(b"\x16"):
                continue
            for rec in iter_handshake_records(payload):
                if not rec or rec[0] != 0x01:
                    continue
                try:
                    info = parse_client_hello(rec)
                except (ParseError, struct.error, IndexError):
                    continue
                dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
                key = f"{dst}|{info['ja3_md5']}|{info['sni']}"
                if key in seen:
                    continue
                seen.add(key)
                print(f"-> {dst}:{int(pkt[TCP].dport)}")
                print(f"   sni       : {info['sni'] or '(none)'}")
                print(f"   version   : {info['version']}")
                print(f"   alpn      : {', '.join(info['alpn']) or '(none)'}")  # type: ignore[arg-type]
                print(f"   ciphers   : {len(info['ciphers'])} offered")  # type: ignore[arg-type]
                print(f"   ja3       : {info['ja3']}")
                print(f"   ja3_md5   : {info['ja3_md5']}")
    if not seen:
        print("no ClientHello records found", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Session resumption** (tickets, PSK) reuses secrets negotiated in an earlier handshake. If that
  handshake is not in the capture and not in the keylog, that session stays encrypted.
- **TLS 1.3 encrypts the certificate**, so `tls.handshake.certificate` is empty without keys. The
  SNI is still cleartext unless ECH is in use.
- **ECH / ESNI** hides the SNI inside an encrypted extension. Fall back to the IP, the JA3, and
  the DNS queries that preceded the connection.
- **QUIC** is TLS 1.3 over UDP. Wireshark decrypts it from the same keylog file; filter with
  `quic` and `http3`.
- The RSA-key route fails silently. If you see no decrypted data, re-check the cipher suite
  before blaming the key.
- Keylog lines must match the **client random in the capture**. A keylog from a different run
  will not decrypt anything even for the same host.
- `-o tls.keylog_file:` needs an absolute path in some builds; relative paths are resolved against
  the profile directory, not the CWD.
- JA3 is not a unique identifier -- every Chrome on the same version shares one. It is a pivot,
  not an attribution.

## Tools

`tshark`, `wireshark`, `editcap` (`--inject-secrets`), `openssl`, `zeek` (ssl.log / x509.log /
ja3 plugin), `scapy`, `mitmproxy` (generates keylogs), `curl`/`firefox`/`chrome` with
`SSLKEYLOGFILE`.

## References

- `man editcap` documents `--inject-secrets tls,<file>`.
- The NSS key log format is described in the NSS source and implemented identically by OpenSSL,
  BoringSSL and Go's `crypto/tls` `KeyLogWriter`.
- `tshark -G fields | grep ja3` shows whether your build exposes the JA3 fields natively.
