---
title: "Network Protocol Reversing - Building a Client for a Custom Service"
category: misc
subcategory: network-services
type: technique
tags: [protocol-reversing, custom-protocol, socket, pwntools, scapy, tshark, pcap, length-prefixed, tlv, struct, netcat, hexdump, network-services]
difficulty: medium
summary: "Probe an unknown TCP/UDP service, work out its framing from hexdumps or a pcap, and build a Python client that speaks it correctly."
when_to_use:
  - "A service on a high port answers with binary or a custom text protocol"
  - "You have a pcap of a client talking to the service and must replay/extend it"
  - "You need to script an interaction that a plain nc session cannot do reliably"
  - "The challenge is 'talk to this daemon and make it give you the flag'"
tools: [netcat, socat, pwntools, scapy, tshark, python3]
related: [net-reverse-shells, net-scanning-fingerprinting, net-legacy-services]
---

## TL;DR

Reversing a network protocol is: probe it by hand, hexdump the responses, identify the **framing**
(newline, fixed header, length prefix, TLV, netstring), find the endianness and any magic/checksum,
then encode that in a Python client. If you have a pcap, extract one full conversation and replay it,
then mutate.

## Recognise it

- nmap shows a service it cannot fingerprint (`unknown` or a bare open port).
- `nc` to the port returns bytes that are not obviously text, or a text prompt with a custom syntax.
- The challenge ships a `.pcap` and a hostname/port.

## Attack

### Step 1 -- probe by hand

```bash
# See what the server says first (does it speak, or wait for you?)
nc -nv 10.10.10.5 31337

# Send a line and watch the reply
printf 'HELLO\n' | nc -nv 10.10.10.5 31337

# Hexdump the raw bytes (reveals framing, non-printables, lengths)
printf 'HELLO\n' | nc -nv 10.10.10.5 31337 | xxd | head

# UDP probe
printf 'PING' | nc -u -nv 10.10.10.5 31337
```

### Step 2 -- identify the framing

Look at the hexdump and ask:

- **Newline-delimited text?** Lines end `0a` (or `0d 0a`). Easiest; split on `\n`.
- **Fixed-length header?** The first N bytes are constant across messages (a magic + type).
- **Length-prefixed?** A 2- or 4-byte integer at the start equals the rest of the message length.
  Check big-endian (`00 00 00 05`) vs little-endian (`05 00 00 00`).
- **TLV (type-length-value)?** Repeating `[type][len][value]` triples.
- **Netstring?** ASCII digits, a colon, the payload, a comma: `5:hello,`.
- **Checksum/magic?** A trailing field that changes when the body changes; a fixed prefix like
  `de ad be ef`.

```bash
# Compare two responses to spot which bytes are constant (header/magic) vs variable
printf 'A\n' | nc -nv 10.10.10.5 31337 | xxd > a.hex
printf 'BB\n' | nc -nv 10.10.10.5 31337 | xxd > b.hex
diff a.hex b.hex
```

### Step 3 -- extract a conversation from a pcap

```bash
# List TCP streams so you can pick the right one
tshark -r capture.pcap -q -z conv,tcp

# Dump one stream's raw payload as hex (follow stream index 0, TCP)
tshark -r capture.pcap -q -z follow,tcp,raw,0

# Just the client->server bytes of a stream, as hex, one packet per line
tshark -r capture.pcap -Y 'tcp.stream==0 && tcp.len>0' -T fields -e tcp.srcport -e data
```

### Step 4 -- build the client

Start from `socket` for full control, or `pwntools` for convenience (`recvuntil`, `recvn`, `p32`).

```bash
# pwntools quick interactive
python3 -c 'from pwn import *; r=remote("10.10.10.5",31337); r.sendline(b"HELLO"); print(r.recvall(timeout=2))'
```

### Step 5 -- replay, mutate, fuzz

- Replay the exact captured bytes; confirm you get the captured response.
- Mutate one field at a time (length, a value, the magic) and diff the response.
- Fuzz: send increasing lengths, boundary integers (0, 1, 0xffff, negative), and malformed frames,
  watching for a crash, an error leak, or an oracle (different response = information).

## Code

### PCAP conversation extractor (tshark-backed)

```python
#!/usr/bin/env python3
"""Extract one TCP stream from a pcap as directional hex/bytes using tshark.

Requires tshark in PATH.

Usage:
    python3 pcap_convo.py capture.pcap [stream_index]
"""
from __future__ import annotations

import subprocess
import sys


def stream_bytes(pcap: str, stream: int) -> list[tuple[str, bytes]]:
    """Return [(direction_srcport, payload_bytes)] for a TCP stream, in order."""
    proc = subprocess.run(
        ["tshark", "-r", pcap, "-Y", f"tcp.stream=={stream} && tcp.len>0",
         "-T", "fields", "-e", "tcp.srcport", "-e", "data"],
        capture_output=True, text=True, timeout=60,
    )
    out: list[tuple[str, bytes]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[1]:
            continue
        srcport, hexdata = parts
        try:
            out.append((srcport, bytes.fromhex(hexdata)))
        except ValueError:
            continue
    return out


def list_streams(pcap: str) -> str:
    """Return tshark's TCP conversation summary."""
    proc = subprocess.run(
        ["tshark", "-r", pcap, "-q", "-z", "conv,tcp"],
        capture_output=True, text=True, timeout=60,
    )
    return proc.stdout


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    pcap = argv[1]
    if len(argv) < 3:
        print(list_streams(pcap))
        print("\n[*] pick a stream index and rerun: python3 pcap_convo.py file.pcap 0")
        return 0
    stream = int(argv[2])
    convo = stream_bytes(pcap, stream)
    if not convo:
        print("[-] no payload in that stream")
        return 0
    first_src = convo[0][0]
    for srcport, payload in convo:
        arrow = ">>>" if srcport == first_src else "<<<"
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
        print(f"{arrow} ({len(payload)} bytes) {payload[:32].hex()}  |{printable[:32]}|")
    # emit a pwntools skeleton pre-filled with the client-side sends
    print("\n# --- pwntools replay skeleton ---")
    print("from pwn import *")
    print(f"r = remote('HOST', PORT)")
    for srcport, payload in convo:
        if srcport == first_src:
            print(f"r.send(bytes.fromhex('{payload.hex()}'))")
        else:
            print(f"r.recvn({len(payload)})  # expected {len(payload)} bytes back")
    print("print(r.recvall(timeout=2))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

### Length-prefixed protocol client

```python
#!/usr/bin/env python3
"""A client for a 4-byte big-endian length-prefixed TCP protocol, with hexdump,
line-mode fallback and an auto-fuzz mode.

Frame on the wire:  [uint32 length][payload of that many bytes]

Usage:
    python3 lp_client.py 10.10.10.5 31337 send HELLO
    python3 lp_client.py 10.10.10.5 31337 fuzz
"""
from __future__ import annotations

import socket
import struct
import sys

TIMEOUT = 5


class LengthPrefixed:
    """Speak a uint32-BE length-prefixed protocol over a TCP socket."""

    def __init__(self, host: str, port: int, endian: str = ">") -> None:
        self.sock = socket.create_connection((host, port), timeout=TIMEOUT)
        self.sock.settimeout(TIMEOUT)
        self.endian = endian  # ">" big-endian, "<" little-endian

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes or raise on short read."""
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed")
            buf += chunk
        return buf

    def send_frame(self, payload: bytes) -> None:
        """Prefix payload with its length and send."""
        header = struct.pack(self.endian + "I", len(payload))
        self.sock.sendall(header + payload)

    def recv_frame(self) -> bytes:
        """Read a length header then that many payload bytes."""
        header = self._recv_exact(4)
        (length,) = struct.unpack(self.endian + "I", header)
        return self._recv_exact(length)

    def close(self) -> None:
        self.sock.close()


def hexdump(data: bytes, width: int = 16) -> str:
    """Return a classic offset/hex/ascii hexdump."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart} |{asciipart}|")
    return "\n".join(lines)


def build_test_server(port: int) -> None:
    """Loopback echo server used by the self-test (length-prefixed)."""
    import threading

    def serve() -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        conn, _ = srv.accept()
        with conn:
            header = conn.recv(4)
            (length,) = struct.unpack(">I", header)
            payload = conn.recv(length)
            reply = b"ECHO:" + payload
            conn.sendall(struct.pack(">I", len(reply)) + reply)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()


def fuzz(host: str, port: int) -> None:
    """Send boundary-value frames and report distinct responses."""
    probes = [b"", b"A", b"A" * 256, b"A" * 4096, b"\x00\x00\x00\x00", bytes(range(256))]
    for probe in probes:
        try:
            client = LengthPrefixed(host, port)
            client.send_frame(probe)
            resp = client.recv_frame()
            print(f"[len {len(probe):>5}] -> {len(resp)} bytes: {resp[:40]!r}")
            client.close()
        except Exception as exc:  # noqa: BLE001 - fuzzing, any failure is a data point
            print(f"[len {len(probe):>5}] -> EXCEPTION {type(exc).__name__}: {exc}")


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--selftest":
        port = 45999
        build_test_server(port)
        client = LengthPrefixed("127.0.0.1", port)
        client.send_frame(b"HELLO")
        resp = client.recv_frame()
        client.close()
        assert resp == b"ECHO:HELLO", resp
        print("[selftest] ok:", resp)
        return 0

    if len(argv) < 4:
        print(__doc__)
        return 1
    host, port, mode = argv[1], int(argv[2]), argv[3]
    if mode == "fuzz":
        fuzz(host, port)
        return 0
    payload = argv[4].encode() if len(argv) > 4 else b""
    client = LengthPrefixed(host, port)
    client.send_frame(payload)
    resp = client.recv_frame()
    print(hexdump(resp))
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Who speaks first.** Some services greet you, others block waiting for input. `recv` with a
  timeout to find out without hanging.
- **Endianness.** A "huge" length like `0x05000000` (83 million) usually means you read a little-
  endian field as big-endian. Flip it.
- **Short reads.** TCP is a stream, not messages -- one `recv` may return a partial frame or two
  frames glued together. Always loop until you have exactly the length you need (see `_recv_exact`).
- **UDP has no framing or reliability.** One datagram = one message; handle timeouts and retransmit.
- **Checksums.** If mutating a field breaks the response, there is probably a checksum/length you
  must recompute. CRC32, sum-of-bytes and XOR are the common ones.
- **Nagle/latency.** For interactive prompts set `TCP_NODELAY` or use pwntools which handles buffering.
- **pwntools helpers** (`p32`, `u32`, `recvuntil`, `recvn`, `flat`) save a lot of struct plumbing.

## Tools

- `nc` / `socat` -- manual probing.
- `xxd` / `hexdump` -- see the bytes.
- `tshark` / `wireshark` -- pull conversations from a pcap; "Follow TCP Stream".
- `scapy` -- craft/parse packets, especially for UDP and non-TCP protocols.
- `pwntools` -- the client-building library (`remote`, `p32`, `recvn`, `recvuntil`).

## References

- The pwntools documentation (`tubes`, `packing`) shipped with the library.
- `man tshark` (the `-z follow,tcp,raw` and `-T fields` options).
- RFC 1700-era framing patterns (TLV, length-prefix) as seen across binary protocols.
