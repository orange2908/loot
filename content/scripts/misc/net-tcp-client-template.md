---
title: "TCP Client Template - Raw Socket and pwntools for Unknown Services"
category: misc
subcategory: network-services
type: script
tags: [tcp-client, socket, pwntools, protocol-reversing, hexdump, length-prefixed, line-protocol, fuzzing, custom-protocol, network-services, template]
summary: "A ready-to-adapt Python client for an unknown TCP service: raw-socket and pwntools versions, hex dumping, line- and length-prefixed handling, and an auto-fuzz mode."
related: [net-custom-protocol-client, net-port-knock-and-scan, net-service-enumeration-cheatsheet]
---

## What this is

A single-file client you copy, point at `host port`, and adapt. It hex-dumps everything, supports
both newline-delimited and 4-byte length-prefixed framing, has a raw-socket path and a pwntools
path, and an `autofuzz` mode that probes boundary inputs and reports which ones change the response.
It ships with a built-in loopback self-test so you can confirm it works with no target.

## Usage

```bash
# Interactive raw-socket session (type lines, see hexdumped replies)
python3 tcp_client.py 10.10.10.5 31337

# Force a framing mode
python3 tcp_client.py 10.10.10.5 31337 --mode line
python3 tcp_client.py 10.10.10.5 31337 --mode lenprefix

# Use the pwntools backend if installed
python3 tcp_client.py 10.10.10.5 31337 --pwn

# Auto-fuzz: send boundary payloads, cluster distinct responses
python3 tcp_client.py 10.10.10.5 31337 --autofuzz

# Run the offline self-test (no target needed)
python3 tcp_client.py --selftest
```

## Script

```python
#!/usr/bin/env python3
"""Adaptable TCP client for an unknown service.

Modes:
  raw (default)  - interactive: read stdin lines, send, hexdump replies
  --mode line    - newline-delimited framing helpers
  --mode lenprefix - 4-byte big-endian length prefix framing
  --pwn          - use pwntools remote() as the transport if available
  --autofuzz     - send boundary payloads and cluster distinct responses
  --selftest     - run offline against a built-in loopback server

Adapt send_probe() / the framing to the target's protocol.
"""
from __future__ import annotations

import argparse
import hashlib
import socket
import struct
import sys
import threading

TIMEOUT = 6.0


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def hexdump(data: bytes, width: int = 16) -> str:
    """Classic offset/hex/ascii hexdump."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart} |{text}|")
    return "\n".join(lines) if lines else "(empty)"


def guess_framing(sample: bytes) -> str:
    """Heuristic: newline -> line, plausible 4-byte length header -> lenprefix."""
    if b"\n" in sample:
        return "line"
    if len(sample) >= 4:
        (be,) = struct.unpack(">I", sample[:4])
        if be == len(sample) - 4:
            return "lenprefix"
    return "raw"


# --------------------------------------------------------------------------- #
# raw-socket transport
# --------------------------------------------------------------------------- #
class RawClient:
    """Thin wrapper over a TCP socket with framing helpers."""

    def __init__(self, host: str, port: int) -> None:
        self.sock = socket.create_connection((host, port), timeout=TIMEOUT)
        self.sock.settimeout(TIMEOUT)

    def recv_some(self, n: int = 4096) -> bytes:
        """Best-effort single read (returns b'' on timeout/close)."""
        try:
            return self.sock.recv(n)
        except (socket.timeout, OSError):
            return b""

    def recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes or raise."""
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed mid-frame")
            buf += chunk
        return buf

    def send_raw(self, data: bytes) -> None:
        self.sock.sendall(data)

    def send_line(self, data: bytes) -> None:
        self.sock.sendall(data + b"\n")

    def recv_line(self) -> bytes:
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = self.sock.recv(1)
            if not chunk:
                break
            buf += chunk
        return buf

    def send_lenprefix(self, payload: bytes, endian: str = ">") -> None:
        self.sock.sendall(struct.pack(endian + "I", len(payload)) + payload)

    def recv_lenprefix(self, endian: str = ">") -> bytes:
        (length,) = struct.unpack(endian + "I", self.recv_exact(4))
        return self.recv_exact(length)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# pwntools transport (optional)
# --------------------------------------------------------------------------- #
def pwn_session(host: str, port: int) -> None:
    """Drop into a pwntools interactive session if pwntools is installed."""
    try:
        from pwn import remote  # type: ignore
    except ImportError:
        print("[-] pwntools not installed; falling back to raw mode")
        interactive(host, port, "raw")
        return
    io = remote(host, port)
    greeting = io.recv(timeout=2)
    if greeting:
        print(hexdump(greeting))
    io.interactive()


# --------------------------------------------------------------------------- #
# interactive loop
# --------------------------------------------------------------------------- #
def interactive(host: str, port: int, mode: str) -> None:
    """Read stdin lines, send per the framing mode, hexdump replies."""
    client = RawClient(host, port)
    greeting = client.recv_some()
    if greeting:
        print("<<< greeting")
        print(hexdump(greeting))
        if mode == "raw":
            mode = guess_framing(greeting)
            print(f"[*] auto-detected framing: {mode}")
    print(f"[*] mode={mode}. Type input, Ctrl-D to quit.")
    try:
        for raw in sys.stdin.buffer:
            payload = raw.rstrip(b"\n")
            if mode == "lenprefix":
                client.send_lenprefix(payload)
                reply = client.recv_lenprefix()
            elif mode == "line":
                client.send_line(payload)
                reply = client.recv_line()
            else:
                client.send_raw(payload)
                reply = client.recv_some()
            print("<<<")
            print(hexdump(reply))
    except (KeyboardInterrupt, ConnectionError) as exc:
        print(f"\n[*] {exc}")
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# auto-fuzz
# --------------------------------------------------------------------------- #
def autofuzz(host: str, port: int, mode: str) -> None:
    """Send boundary payloads, cluster responses by hash, flag distinct ones."""
    probes = [
        b"", b"A", b"AAAA", b"A" * 256, b"A" * 4096,
        b"\x00", b"\xff\xff\xff\xff", bytes(range(256)),
        b"%s%s%s%s", b"'", b"../../../../etc/passwd", b"{}", b"\n\n",
    ]
    clusters: dict[str, list[str]] = {}
    if mode == "raw":
        mode = "line"  # sane default for fuzzing text services
    for probe in probes:
        try:
            client = RawClient(host, port)
            client.recv_some()  # discard greeting
            if mode == "lenprefix":
                client.send_lenprefix(probe)
                reply = client.recv_lenprefix()
            elif mode == "line":
                client.send_line(probe)
                reply = client.recv_some()
            else:
                client.send_raw(probe)
                reply = client.recv_some()
            digest = hashlib.sha1(reply).hexdigest()[:10]
            clusters.setdefault(digest, []).append(f"len={len(probe)} {probe[:20]!r}")
            print(f"[probe len={len(probe):>5}] -> {len(reply):>5}b  hash={digest}  {reply[:40]!r}")
            client.close()
        except Exception as exc:  # noqa: BLE001 - fuzzing: every failure is a signal
            print(f"[probe len={len(probe):>5}] -> EXCEPTION {type(exc).__name__}: {exc}")

    print("\n=== response clusters (distinct hashes = interesting) ===")
    for digest, members in sorted(clusters.items(), key=lambda kv: len(kv[1])):
        tag = "DISTINCT" if len(members) == 1 else "common"
        print(f"[{tag}] {digest} x{len(members)}: {members}")


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #
def _loopback_line_server(port: int) -> None:
    """A tiny newline-echo server for the self-test."""
    def serve() -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        conn, _ = srv.accept()
        with conn:
            conn.sendall(b"WELCOME\n")
            data = conn.recv(1024)
            conn.sendall(b"ECHO:" + data)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()


def selftest() -> int:
    """Verify the raw client against a loopback echo server."""
    port = 46001
    _loopback_line_server(port)
    client = RawClient("127.0.0.1", port)
    greeting = client.recv_some()
    assert greeting == b"WELCOME\n", greeting
    client.send_line(b"ping")
    reply = client.recv_some()
    client.close()
    assert reply == b"ECHO:ping\n", reply
    print("[selftest] ok:", greeting.strip(), reply.strip())
    return 0


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description="TCP client template for unknown services")
    parser.add_argument("host", nargs="?", help="target host")
    parser.add_argument("port", nargs="?", type=int, help="target port")
    parser.add_argument("--mode", choices=["raw", "line", "lenprefix"], default="raw")
    parser.add_argument("--pwn", action="store_true", help="use pwntools transport")
    parser.add_argument("--autofuzz", action="store_true", help="boundary-value fuzzing")
    parser.add_argument("--selftest", action="store_true", help="run offline self-test")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.host or not args.port:
        parser.print_help()
        return 1
    if args.pwn:
        pwn_session(args.host, args.port)
        return 0
    if args.autofuzz:
        autofuzz(args.host, args.port, args.mode)
        return 0
    interactive(args.host, args.port, args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Adapting it

- Replace the framing in `interactive`/`autofuzz` with the real protocol once you know it
  (TLV, netstring, fixed header). `struct.pack`/`unpack` cover binary fields.
- For a binary protocol, switch `--mode lenprefix` or write a custom send/recv pair.
- For stateful protocols (login, sequence numbers), extend `RawClient` with the handshake.
- Use `--pwn` to get pwntools' `recvuntil`, `recvn`, `p32`/`u32` helpers for exploit development.
