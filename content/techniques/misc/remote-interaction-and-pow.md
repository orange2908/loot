---
title: "Remote Interaction and Proof-of-Work Gates"
category: misc
subcategory: networking
type: technique
tags: [pwntools, remote, socket, netcat, proof-of-work, pow, hashcash, redpwnpow, kctf, sha256, speed-challenge, recvuntil, sendlineafter, interactive, automation]
difficulty: medium
summary: "Connect, solve the PoW gate, then loop: recvuntil the prompt, parse, compute, sendline - with a template that works with or without pwntools."
when_to_use:
  - "The challenge is `nc host port` and asks you to solve N problems in M seconds"
  - "The service prints a proof-of-work challenge before the real one"
  - "You need to script an interaction that a human cannot do fast enough"
  - "pwntools is unavailable and you need a stdlib fallback"
tools: [pwntools, python3, nc, socat, hashcash, kctf-pow]
related: [pow-solver, ctf-general-cheatsheet, misc-classics, python-jail-escape, jail-escape-payloads]
---

## TL;DR

Three phases, always in this order: **connect -> clear the gate -> loop the real challenge**.
Get the gate out of the way first (it is usually a hashed proof-of-work), then write a tight
`recvuntil`/`sendline` loop. Print everything you receive while developing; turn logging down
only once it works.

## Recognise it

```text
== proof-of-work: curl -sSfL https://pwn.red/pow | sh -s s.AAA...   ==
```
```text
== proof-of-work: ==
python3 <(curl -sSL https://goo.gle/kctf-pow) solve s.524288.XXXX
```
```text
hashcash -mb28 -r <resource>
```
```text
Provide a string S such that sha256(S)[:6] == "000000"
Provide a hex string X such that sha256(prefix + X) starts with 20 zero bits
```

If the banner mentions `pow`, `hashcash`, `proof of work`, `zero bits`, or gives you a prefix
and a difficulty, it is a gate, not the challenge.

## The common proof-of-work forms

| Form | What to compute |
| --- | --- |
| **leading hex zeros** | find `s` with `sha256(prefix + s).hexdigest().startswith("0"*n)` |
| **leading zero bits** | same but on the bit representation: `int(h,16) < 2**(256-n)` |
| **suffix zeros** | `endswith("0"*n)` - same search, different check |
| **fixed-length answer** | the server dictates the length/alphabet of `s` |
| **hashcash** | `hashcash -mb<bits> -r <resource>` produces a stamp of the form `1:bits:date:resource::rand:counter` whose SHA-1 has `bits` leading zero bits |
| **redpwnpow** | challenge `s.<difficulty>.<b64>`; the answer is `s.<b64 of the result>`; the reference solver is the `pwn.red/pow` script |
| **kctf pow.py** | challenge `s.<difficulty>.<b64 chal>`; solved with `kctf-pow solve <chal>`; internally it is a repeated-squaring VDF, not a hash search |

The hash-search forms are the ones you can reimplement in ten lines. redpwnpow and kctf define
their own encodings - use their official solver script when you can reach the network, and see
the `pow-solver` script entry for reimplementations.

## Attack

### 1. Look before you script

```bash
# see exactly what the service sends, bytes and all
nc host 1337 | xxd | head -40
# keep stdin open and interactive
nc -v host 1337
# TLS services
openssl s_client -connect host:1337 -quiet
socat - OPENSSL:host:1337,verify=0
# record a session for replay
socat -v - TCP:host:1337 2>session.log
```

Note whether the prompt ends with a newline, a space, or nothing - `recvuntil` needs the exact
bytes. `\n` vs `\r\n` matters.

### 2. Clear the gate

```bash
# the official solvers, when the box has network access
curl -sSfL https://pwn.red/pow | sh -s <challenge>
python3 <(curl -sSL https://goo.gle/kctf-pow) solve <challenge>
hashcash -mb28 -r <resource>
```

Offline, compute it yourself (see the code below and the `pow-solver` script).

### 3. Loop the challenge

Use `recvuntil` on a stable anchor, parse with a regex, compute, `sendline`. Never
`recv(1024)` and hope.

## Code

A complete, dependency-free client plus the pwntools equivalent, with a local test server so
the self-test actually exercises the loop.

```python
#!/usr/bin/env python3
"""Remote-challenge client: PoW solver + interactive loop, stdlib only.

  python3 remote_client.py host port
  python3 remote_client.py --selftest        # runs a local server and solves it
"""
from __future__ import annotations

import hashlib
import multiprocessing as mp
import re
import socket
import socketserver
import string
import sys
import threading
import time

# --------------------------------------------------------------------------- #
# proof of work
# --------------------------------------------------------------------------- #
ALPHABET = (string.ascii_letters + string.digits).encode()


def _pow_worker(args):
    prefix, nzeros, mode, algo, start, step, limit = args
    h = getattr(hashlib, algo)
    target_hex = "0" * nzeros
    for i in range(start, limit, step):
        cand = _encode(i)
        digest = h(prefix + cand).hexdigest()
        if mode == "prefix" and digest.startswith(target_hex):
            return cand
        if mode == "suffix" and digest.endswith(target_hex):
            return cand
        if mode == "bits" and int(digest, 16) < (1 << (h().digest_size * 8 - nzeros)):
            return cand
    return None


def _encode(i: int) -> bytes:
    """Bijective base-62 encoding of i, used to enumerate candidates."""
    if i == 0:
        return ALPHABET[:1]
    out = bytearray()
    n = len(ALPHABET)
    while i:
        out.append(ALPHABET[i % n])
        i //= n
    return bytes(reversed(out))


def solve_pow(prefix: bytes, nzeros: int, mode: str = "prefix",
              algo: str = "sha256", jobs: int = 0, limit: int = 1 << 40) -> bytes:
    """Find a suffix whose hash meets the condition. Single-process for tiny difficulties."""
    jobs = jobs or 1
    if nzeros <= 4 or jobs == 1:
        return _pow_worker((prefix, nzeros, mode, algo, 0, 1, limit)) or b""
    with mp.Pool(jobs) as pool:
        tasks = [(prefix, nzeros, mode, algo, k, jobs, limit) for k in range(jobs)]
        for res in pool.imap_unordered(_pow_worker, tasks):
            if res:
                pool.terminate()
                return res
    return b""


def parse_pow(banner: bytes) -> tuple[bytes, int, str] | None:
    """Best-effort parse of the common textual PoW descriptions."""
    m = re.search(rb"sha256\(\s*[\"']?([A-Za-z0-9+/=_-]{4,})[\"']?\s*\+", banner, re.I)
    prefix = m.group(1) if m else b""
    m = re.search(rb"(\d+)\s*(?:leading\s*)?zero\s*bits", banner, re.I)
    if m:
        return prefix, int(m.group(1)), "bits"
    m = re.search(rb"starts?\s+with\s+(\d+)\s+zero", banner, re.I)
    if m:
        return prefix, int(m.group(1)), "prefix"
    m = re.search(rb"==\s*[\"'](0+)[\"']", banner)
    if m:
        return prefix, len(m.group(1)), "prefix"
    m = re.search(rb"ends?\s+with\s+(\d+)\s+zero", banner, re.I)
    if m:
        return prefix, int(m.group(1)), "suffix"
    return None


# --------------------------------------------------------------------------- #
# a minimal tube: recvuntil / sendline over a plain socket
# --------------------------------------------------------------------------- #
class Tube:
    def __init__(self, host: str, port: int, timeout: float = 20.0, verbose: bool = False):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.verbose = verbose

    def recv(self, n: int = 4096) -> bytes:
        data = self.sock.recv(n)
        if self.verbose and data:
            sys.stderr.write(data.decode("utf-8", "replace"))
        return data

    def recvuntil(self, delim: bytes, timeout: float = 20.0) -> bytes:
        end = time.time() + timeout
        while delim not in self.buf:
            remaining = end - time.time()
            if remaining <= 0:
                raise TimeoutError(f"never saw {delim!r}; buffer tail: {self.buf[-200:]!r}")
            # the socket timeout must track the deadline, otherwise a blocking recv
            # overshoots it and the server gives up on us first
            self.sock.settimeout(max(0.05, remaining))
            try:
                chunk = self.recv()
            except (socket.timeout, TimeoutError) as exc:
                raise TimeoutError(
                    f"never saw {delim!r}; buffer tail: {self.buf[-200:]!r}") from exc
            if not chunk:
                raise EOFError(f"connection closed; buffer tail: {self.buf[-200:]!r}")
            self.buf += chunk
        idx = self.buf.index(delim) + len(delim)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def recvline(self, timeout: float = 20.0) -> bytes:
        return self.recvuntil(b"\n", timeout)

    def send(self, data: bytes) -> None:
        if self.verbose:
            sys.stderr.write(f"\x1b[33m{data.decode('utf-8', 'replace')}\x1b[0m")
        self.sock.sendall(data)

    def sendline(self, data: bytes) -> None:
        self.send(data + b"\n")

    def sendlineafter(self, delim: bytes, data: bytes) -> bytes:
        got = self.recvuntil(delim)
        self.sendline(data)
        return got

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# the solve loop
# --------------------------------------------------------------------------- #
PROBLEM_RE = re.compile(rb"([-\d]+)\s*([+\-*/%])\s*([-\d]+)")


def solve_expression(text: bytes) -> bytes | None:
    m = PROBLEM_RE.search(text)
    if not m:
        return None
    a, op, b = int(m.group(1)), m.group(2).decode(), int(m.group(3))
    val = {"+": a + b, "-": a - b, "*": a * b,
           "/": a // b if b else 0, "%": a % b if b else 0}[op]
    return str(val).encode()


def run(host: str, port: int, rounds: int = 200, verbose: bool = False) -> bytes | None:
    t = Tube(host, port, verbose=verbose)
    banner = t.recvuntil(b"\n")
    for _ in range(4):                     # read a few more banner lines if present
        try:
            banner += t.recvuntil(b"\n", timeout=1.0)
        except (TimeoutError, EOFError):
            break

    parsed = parse_pow(banner)
    if parsed:
        prefix, bits, mode = parsed
        sys.stderr.write(f"[*] PoW: prefix={prefix!r} n={bits} mode={mode}\n")
        answer = solve_pow(prefix, bits, mode, jobs=mp.cpu_count())
        sys.stderr.write(f"[+] PoW answer: {answer!r}\n")
        t.sendline(answer)

    flag = None
    for i in range(rounds):
        try:
            chunk = t.recvuntil(b"\n")
        except (EOFError, TimeoutError) as exc:
            sys.stderr.write(f"[!] {exc}\n")
            break
        if b"flag{" in chunk.lower() or b"ctf{" in chunk.lower():
            flag = chunk.strip()
            sys.stderr.write(f"[+] FLAG: {flag!r}\n")
            break
        ans = solve_expression(chunk)
        if ans is not None:
            t.sendline(ans)
    t.close()
    return flag


# --------------------------------------------------------------------------- #
# pwntools equivalent (for reference; not executed by the self-test)
# --------------------------------------------------------------------------- #
PWNTOOLS_TEMPLATE = r'''
from pwn import *
import re

context.log_level = "info"          # "debug" while developing
io = remote(args.HOST or "host", int(args.PORT or 1337))
# io = process("./chal")            # local testing
# io = remote("host", 1337, ssl=True)

banner = io.recvuntil(b"\n")
if b"proof" in banner.lower():
    # solve the gate, then send the answer
    io.sendlineafter(b"solution: ", solve_pow(...))

for _ in range(200):
    line = io.recvuntil(b"= ", timeout=10)
    a, op, b = re.search(rb"(-?\d+) ([-+*/]) (-?\d+)", line).groups()
    io.sendline(str(eval(f"{int(a)}{op.decode()}{int(b)}")).encode())

io.interactive()
'''


# --------------------------------------------------------------------------- #
# self-test: a local server that gates on a PoW then asks arithmetic questions
# --------------------------------------------------------------------------- #
class _Handler(socketserver.StreamRequestHandler):
    timeout = 20
    prefix = b"abc123"
    nzeros = 3
    rounds = 12

    def handle(self) -> None:
        self.wfile.write(
            b"== proof-of-work ==\n"
            b"find s such that sha256('" + self.prefix + b"' + s) starts with "
            + str(self.nzeros).encode() + b" zeros\n"
            b"solution: ")
        answer = self.rfile.readline().strip()
        digest = hashlib.sha256(self.prefix + answer).hexdigest()
        if not digest.startswith("0" * self.nzeros):
            self.wfile.write(b"bad pow\n")
            return
        self.wfile.write(b"ok\n")
        for i in range(self.rounds):
            a, b = 1234 + i * 7, 56 + i
            self.wfile.write(f"{a} * {b} = ".encode() + b"\n")
            reply = self.rfile.readline().strip()
            if reply != str(a * b).encode():
                self.wfile.write(b"wrong\n")
                return
        self.wfile.write(b"flag{remote_loop_ok}\n")


def _selftest() -> None:
    # encoding is injective and deterministic
    seen = {_encode(i) for i in range(1000)}
    assert len(seen) == 1000

    # PoW solving actually satisfies the predicate
    ans = solve_pow(b"abc123", 3, "prefix")
    assert hashlib.sha256(b"abc123" + ans).hexdigest().startswith("000"), ans
    ans_b = solve_pow(b"xyz", 12, "bits")
    assert int(hashlib.sha256(b"xyz" + ans_b).hexdigest(), 16) < (1 << (256 - 12))
    ans_s = solve_pow(b"q", 2, "suffix")
    assert hashlib.sha256(b"q" + ans_s).hexdigest().endswith("00")

    # banner parsing
    p = parse_pow(b"find s such that sha256('abc123' + s) starts with 3 zeros\n")
    assert p == (b"abc123", 3, "prefix"), p
    p = parse_pow(b"give a token with 20 leading zero bits\n")
    assert p is not None and p[1] == 20 and p[2] == "bits", p
    assert parse_pow(b"no pow here\n") is None

    # expression solving
    assert solve_expression(b"1234 * 56 = ") == b"69104"
    assert solve_expression(b"what is -5 + 12 ?") == b"7"
    assert solve_expression(b"no problem here") is None

    # end-to-end against a local server
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    host, port = srv.server_address
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        flag = run(host, port, rounds=40)
    finally:
        srv.shutdown()
        srv.server_close()
    assert flag == b"flag{remote_loop_ok}", flag

    assert "pwn import" in PWNTOOLS_TEMPLATE
    print(f"selftest ok: pow solved ({ans!r}), banner parsed, end-to-end flag {flag!r}")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    flag = run(host, port, verbose=True)
    return 0 if flag else 1


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **Buffering.** If the server uses Python `print` without `flush=True` behind a pipe, output
  arrives in 4 KB blocks. There is nothing you can do from the client - but recognise it so you
  do not blame your `recvuntil`.
- **`\r\n` vs `\n`.** Services written for `telnet` send CRLF. `recvuntil(b"\n")` still works,
  but your parsed line has a trailing `\r`; strip it.
- **Anchor on something stable.** `recvuntil(b"> ")` breaks the moment the prompt changes.
  Prefer a regex over accumulated text when the format varies.
- **Timeouts kill long PoWs.** Solve the PoW *before* connecting when the challenge string is
  given on the command line; when it is delivered over the socket, make sure your solver is
  fast enough (multi-process) or the server will drop you.
- **Difficulty units differ.** "20 zeros" usually means 20 *hex* zeros (80 bits - impossible)
  or 20 *bits* (instant). If your solver hangs, you probably misread the unit.
- **Rate limiting / one connection per PoW.** Some services require a fresh PoW per connection;
  cache nothing.
- **`io.interactive()`** at the end of a pwntools script is how you catch a flag printed after
  the loop; without it the process exits and you lose the output.
- **Log while developing.** `context.log_level = "debug"` in pwntools, or `verbose=True` in the
  Tube above, shows every byte in both directions.
- **Speed challenges**: precompute what you can before connecting, and avoid per-round
  `print`/flush on your side. Python is fast enough for a few thousand arithmetic rounds.
- **eval on server-provided expressions** is a real risk if the server is hostile; parse with a
  regex or an AST whitelist instead (see `eval-jail-generic`).

## Tools

`pwntools` (`pip install pwntools`), `nc`/`ncat`, `socat`, `openssl s_client`,
`hashcash`, `kctf-pow`, the `pow-solver` script in this knowledge base.

## References

- pwntools documentation for `remote`, `recvuntil`, `sendlineafter` and `interactive`:
  https://docs.pwntools.com/
- The hashcash stamp format, as documented in the `hashcash` manual page.
- Python `hashlib` and `multiprocessing` documentation for the solver.
