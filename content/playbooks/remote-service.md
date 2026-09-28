---
title: "Playbook - I Have `nc host port`"
category: misc
subcategory: triage
type: playbook
tags: [nc-service, remote-service, netcat, where-to-start, stuck, fingerprint, proof-of-work, pow, interactive-protocol, pwntools, socket, tls, banner, oracle, jail, pyjail, what-attack]
summary: "Fingerprint any remote service, detect a proof-of-work gate and an interactive protocol, and route to the right attack family."
when_to_use:
  - "The challenge gives you a host and a port and nothing else"
  - "The service asks for a proof of work before doing anything"
  - "You need a scriptable harness for an interactive remote protocol"
related: [crypto-triage, pwn-triage, web-triage, pwntools, nmap]
---

## TL;DR

```sh
HOST=chal.ctf; PORT=1337
# 1. Just look at it. Half of all services tell you exactly what they are.
nc -v $HOST $PORT
# 2. If nothing appears within 3 seconds, it is waiting for you. Send a newline.
printf '\n' | nc $HOST $PORT | head -40
# 3. Is it TLS?
openssl s_client -connect $HOST:$PORT -quiet 2>&1 | head -30
# 4. Is it HTTP?
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$HOST" | nc $HOST $PORT | head -40
# 5. Does it echo? Does it crash?
python3 -c "print('A'*5000)" | nc $HOST $PORT | head -20
```

---

## Section 1 - Fingerprint decision tree

```
Connect with `nc -v host port`.
 |
 |-- Connection refused / times out
 |     -> wrong host/port, or the service is UDP: `nc -u host port`
 |     -> or you need the CTF VPN up
 |
 |-- It prints a banner immediately
 |     |-- ASCII art + a numbered menu           -> pwn heap/stack challenge  (Section 4)
 |     |-- "n = 123...", "e = 65537", "c = ..."  -> crypto           (`ctfbrain search crypto-triage`)
 |     |-- "Give me a string that hashes to..."  -> proof of work    (Section 3)
 |     |-- A Python `>>>` or `Enter code:`       -> pyjail           (`ctfbrain search pyjail`)
 |     |-- A shell-like prompt `$ `              -> shell escape / restricted shell
 |     |-- "HTTP/1.1"                            -> web              (`ctfbrain search web-triage`)
 |     |-- "SSH-2.0-..."                         -> SSH: check version for CVEs, or creds are the challenge
 |     |-- "220 ... FTP"                         -> FTP: anonymous login, then `ls -la`
 |     |-- "* OK IMAP" / "+OK POP3"              -> mail
 |     |-- "220 ... SMTP"                        -> SMTP: VRFY/EXPN enumeration, or send mail
 |     |-- Binary garbage                        -> a custom binary protocol (Section 5)
 |     |-- A single line then closes             -> stateless oracle: script it (Section 2)
 |
 |-- It prints nothing and waits
 |     -> send "\n", then "help\n", then "A"*100 + "\n", then random bytes
 |     -> if it echoes back what you send: an echo/format-string/crypto oracle
 |     -> if it closes on invalid input: enumerate the accepted commands
 |
 |-- It prints nothing and closes immediately
       -> it expects data first, in a specific format. Read the handout source again.
```

Port-number hints: see `ctfbrain search common-ports-services`.

---

## Section 2 - The universal harness

Start every remote challenge with this. Do not use raw `nc` for anything past the first look.

```python
#!/usr/bin/env python3
"""Generic remote-service harness. Usage: ./solve.py [host] [port]"""
from pwn import remote, context, log
import sys, re

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
context.log_level = "debug"      # set to "info" once it works

def connect():
    io = remote(HOST, PORT)
    # io = remote(HOST, PORT, ssl=True)          # if TLS
    return io

def banner(io, timeout=2.0):
    data = io.recvrepeat(timeout)
    print(data.decode(errors="replace"))
    return data

def ask(io, payload: bytes, prompt: bytes = b"> ") -> bytes:
    io.sendlineafter(prompt, payload)
    return io.recvline()

if __name__ == "__main__":
    io = connect()
    b = banner(io)
    # auto-detect a proof-of-work gate
    if re.search(rb"proof.of.work|pow|hashcash|sha256\(|sha-?1\(|md5\(", b, re.I):
        log.warn("proof of work detected - see Section 3")
    io.interactive()
```

Rules that save time:
- Use `recvuntil` with a **unique** anchor, never `recv(n)`.
- Use `sendlineafter(prompt, data)` so you never desynchronise.
- Set `context.log_level = "debug"` while building; it prints every byte in both directions.
- Wrap the connection in a function so you can reconnect in a loop (oracles need hundreds of connections).
- `io.interactive()` at the end so you can drive it by hand once the automation gets you in.

---

## Section 3 - Proof-of-work gates

A PoW gate looks like one of these:

| Prompt | Meaning | Solver |
|---|---|---|
| `sha256(XXXX+???) ends with 000000` | find a suffix so the hash has N trailing zero **hex chars** | brute force below |
| `sha256(prefix + s).hexdigest().startswith('0000')` | leading zeros | brute force below |
| `hashcash -mb26 -r <resource>` | the hashcash tool | `hashcash -mb26 -r <resource>` |
| `python3 <(curl -sSL https://goo.gle/kctf-pow) solve <challenge>` | kCTF PoW | run the command they print, verbatim |
| `redpwnpow` / `proof-of-work.py` | the challenge ships the solver | run the command they print |
| `Find x such that x % N == 0 and ...` | an arithmetic puzzle | solve directly |
| `Solve: 4 + 7 * 2` | a simple captcha | `eval` the expression (safely) |

Generic brute-forcer (covers the two most common forms):

```python
#!/usr/bin/env python3
"""Solve the common 'hash(prefix + X) has property P' proof-of-work gates."""
import hashlib
import itertools
import string
import re

ALPHABET = string.ascii_letters + string.digits


def solve_pow(prefix: str, nzeros: int, algo: str = "sha256",
              position: str = "suffix", target_char: str = "0") -> str:
    """Return the string S such that algo(prefix+S) (or algo(S+prefix)) has
    nzeros leading/trailing `target_char` in its hex digest."""
    h = getattr(hashlib, algo)
    for length in range(1, 12):
        for tup in itertools.product(ALPHABET, repeat=length):
            s = "".join(tup)
            data = (prefix + s) if position == "suffix" else (s + prefix)
            d = h(data.encode()).hexdigest()
            if d.startswith(target_char * nzeros):
                return s
    raise RuntimeError("not found")


def solve_pow_trailing(prefix: str, nzeros: int, algo: str = "sha256") -> str:
    h = getattr(hashlib, algo)
    for length in range(1, 12):
        for tup in itertools.product(ALPHABET, repeat=length):
            s = "".join(tup)
            if h((prefix + s).encode()).hexdigest().endswith("0" * nzeros):
                return s
    raise RuntimeError("not found")


def parse_challenge(line: str):
    """Best-effort parse of a PoW prompt. Returns (algo, prefix, nzeros)."""
    algo = "sha256"
    m = re.search(r"(md5|sha1|sha256|sha512)", line, re.I)
    if m:
        algo = m.group(1).lower()
    pre = ""
    m = re.search(r"[\"']?([A-Za-z0-9+/=]{6,})[\"']?", line)
    if m:
        pre = m.group(1)
    n = 6
    m = re.search(r"(\d+)\s*(?:leading|trailing)?\s*zero", line, re.I)
    if m:
        n = int(m.group(1))
    else:
        m = re.search(r"(0{3,})", line)
        if m:
            n = len(m.group(1))
    return algo, pre, n


if __name__ == "__main__":
    # self-test
    pre = "abcd"
    s = solve_pow(pre, 4)
    assert hashlib.sha256((pre + s).encode()).hexdigest().startswith("0000")
    print("ok:", s, hashlib.sha256((pre + s).encode()).hexdigest())
```

Expected work: N leading hex zeros costs ~`16^N` hashes. 4 zeros is instant, 5 is ~1s, 6 is ~17s single-threaded, 7 is ~5 minutes. If the gate asks for more than 6, use `multiprocessing` or write it in C.

Multiprocess version:
```python
from multiprocessing import Pool, cpu_count
import hashlib, os

def worker(args):
    prefix, nzeros, seed = args
    i = seed
    tgt = "0" * nzeros
    while True:
        s = f"{i:x}"
        if hashlib.sha256((prefix + s).encode()).hexdigest().startswith(tgt):
            return s
        i += cpu_count()

def fast_pow(prefix, nzeros):
    with Pool(cpu_count()) as p:
        return p.imap_unordered(worker, [(prefix, nzeros, k) for k in range(cpu_count())]).next()
```

**Always cache the PoW answer per connection** if the service lets you reuse it, and solve it inside your `connect()` so every reconnection is automatic:
```python
def connect():
    io = remote(HOST, PORT)
    line = io.recvline().decode()
    if "sha256" in line.lower():
        algo, prefix, n = parse_challenge(line)
        io.sendlineafter(b"?", solve_pow(prefix, n, algo).encode())
    return io
```

---

## Section 4 - Menu-driven services (pwn / heap)

```
1. Create
2. Edit
3. Show
4. Delete
5. Exit
```
This shape means a heap challenge. Map the menu to primitives:

| Menu item | Primitive |
|---|---|
| Create/Add/Malloc | `malloc(size)` with a size you choose |
| Edit/Update/Write | write into a chunk - check whether the length is re-read (heap overflow) |
| Show/Print/View | read a chunk - the leak source if used after free |
| Delete/Free/Remove | `free(p)` - check whether the pointer is nulled (UAF / double free) |

```python
def add(io, idx, size, data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"data: ", data)

def free(io, idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"index: ", str(idx).encode())

def show(io, idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", str(idx).encode())
    return io.recvline()
```
Then `ctfbrain search pwn-triage`.

---

## Section 5 - Reverse an unknown binary protocol

```sh
# 1. capture what a legitimate client sends, if one is provided
tcpdump -i any -w proto.pcap host $HOST and port $PORT
# 2. or just observe the framing
python3 - <<'PY'
import socket
s = socket.create_connection(("chal.ctf", 1337), timeout=5)
s.sendall(b"\n")
data = s.recv(4096)
print(len(data), data[:64].hex(" "), data[:64])
PY
```
Framing patterns to look for:
- First 2 or 4 bytes are a length (big-endian usually): `struct.unpack(">I", data[:4])`
- A magic constant at the start of every message
- Null-terminated strings
- Type-Length-Value records
- JSON or msgpack (`\x82\xa4` style prefix) or protobuf (field tags `\x08`, `\x12`, `\x1a`)

```python
# protobuf-ish? try:
# pip install protobuf blackboxprotobuf
import blackboxprotobuf
msg, typedef = blackboxprotobuf.decode_message(data)
print(msg)
```

---

## Section 6 - Probing checklist

Run through this list on any service you cannot classify:

```sh
# Does it take long input?      (overflow)
python3 -c "print('A'*10000)" | nc $HOST $PORT
# Does it interpret format specifiers?  (format string)
printf '%%p %%p %%p %%p %%p %%p %%p %%p\n' | nc $HOST $PORT
# Does it evaluate arithmetic?   (eval / template / jail)
printf '7*7\n{{7*7}}\n${7*7}\n<%%= 7*7 %%>\n' | nc $HOST $PORT
# Does it run shell commands?    (command injection)
printf 'a; id\na | id\na`id`\n$(id)\n' | nc $HOST $PORT
# Does it accept path names?     (traversal)
printf '../../../../etc/passwd\n' | nc $HOST $PORT
# Does it accept SQL?            
printf "' OR 1=1--\n" | nc $HOST $PORT
# Does it leak on error?         (compare error strings)
printf 'zzzz\n' | nc $HOST $PORT
# Does it time out differently per input?  (timing oracle)
for c in a b c d; do /usr/bin/time -f "$c %e" sh -c "printf '$c\n' | nc -w2 $HOST $PORT >/dev/null"; done
```

---

## Section 7 - Practical gotchas

| Problem | Fix |
|---|---|
| `nc` hangs after sending | the service wants `\r\n`; use `printf 'x\r\n'` or `io.send(b"x\r\n")` |
| Output is buffered and arrives all at once | normal for a remote; use `recvrepeat`/`recvuntil`, not `recv` |
| Works with `nc` but not pwntools | pwntools sends `\n` with `sendline`; the service may need `\r\n` -> `context.newline = b"\r\n"` |
| Connection drops after N seconds | there is an `alarm()`; your exploit must be fast, or reconnect per query |
| Rate limited / IP banned | add a delay, or reuse one connection for many queries |
| TLS required | `remote(host, port, ssl=True, sni=host)` |
| UDP service | `remote(host, port, typ="udp")` |
| Works locally, fails remote | see `ctfbrain search pwn-triage` section 8 |
| You need many parallel connections | `concurrent.futures.ThreadPoolExecutor` around your `connect()`; watch for server-side limits |
| The service is behind a "gateway" that multiplexes | read the handout `Dockerfile`/`xinetd.conf` for the real command |

If you have the handout source, read it before probing: `ctfbrain search source-code-given`.
Still lost: `ctfbrain search stuck`
