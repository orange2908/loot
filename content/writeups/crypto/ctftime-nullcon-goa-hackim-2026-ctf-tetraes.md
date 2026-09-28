---
title: "Tetraes - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "cry", "aes", "tetraes", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40650"
  url: "https://ctftime.org/writeup/40650"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Tetraes/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Tetraes"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Tetraes
- **Author team:** RootRunners
- **CTFtime tags:** cry
- **CTFtime:** <https://ctftime.org/writeup/40650>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Tetraes/README.md>

---
# Tetraes

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Crypto   
**Points:** 251   
**Service:** `52.59.124.14:5103`   
**Files:** `[chall.py](http://chall.py)`

## Overview  
The service implements a custom AES-like block cipher and exposes an encryption oracle. At startup it prints `encrypt(key, key)` and then allows chosen-plaintext queries under the same secret 16-byte key. The cipher uses an S-box with a collision, making it non-injective and enabling key recovery.

## Vulnerability  
The S-box is not a permutation:  
\- `S[0x00] == 0x64`  
\- `S[0x8c] == 0x64`

So inputs `0x00` and `0x8c` collide in the SubBytes step. By crafting inputs that force a single byte entering SubBytes to be either `0x00` or `0x8c`, we can detect collisions and derive two candidates for each key byte.

## Key Recovery Strategy  
1\. For each byte position `pos`, find a plaintext byte `p` such that:  
\- `encrypt(block with p at pos) == encrypt(block with (p ^ 0x8c) at pos)`  
2\. This implies the SubBytes input at that position is either `0x00` or `0x8c`, giving two candidates for the corresponding key byte.  
3\. For byte 0, the initial round also xors `42`, so candidates are:  
\- `p ^ 42` and `p ^ 42 ^ 0x8c`  
4\. There are `2^16` total key candidates. Use the leaked `encrypt(key, key)` at startup to pick the correct one by local recomputation.

## Solver (Python)  
```python  
#!/usr/bin/env python3  
import argparse  
import itertools  
import socket  
import sys  
import time  
from typing import Optional

from chall import encrypt

COLLISION_DELTA = 0x8C # S[0x00] == S[0x8C]  
ARK_CONST = 42 # state[0][0] ^= r ^ 42, with r=0 in first ARK

class Remote:  
def __init__(self, host: str, port: int, timeout: float = 5.0):  
self.sock = socket.create_connection((host, port), timeout=timeout)  
self.sock.settimeout(timeout)  
self.buf = bytearray()

def close(self) -> None:  
try:  
self.sock.close()  
except Exception:  
pass

def _recv_more(self) -> None:  
chunk = self.sock.recv(4096)  
if not chunk:  
raise EOFError("connection closed")  
self.buf.extend(chunk)

def read_until(self, token: bytes) -> bytes:  
while True:  
idx = self.buf.find(token)  
if idx != -1:  
end = idx + len(token)  
out = bytes(self.buf[:end])  
del self.buf[:end]  
return out  
self._recv_more()

def read_line(self) -> bytes:  
while True:  
idx = self.buf.find(b"\n")  
if idx != -1:  
out = bytes(self.buf[: idx + 1])  
del self.buf[: idx + 1]  
return out  
self._recv_more()

def send_line(self, line: str) -> None:  
if not line.endswith("\n"):  
line += "\n"  
self.sock.sendall(line.encode())

def parse_cipher_line(line: bytes) -> bytes:  
s = line.decode(errors="ignore").strip()  
if "cipher.hex()" not in s:  
raise ValueError(f"not a cipher line: {s!r}")  
if "'" in s:  
parts = s.split("'")  
if len(parts) >= 2:  
return bytes.fromhex(parts[1])  
hx = s.split("=")[-1].strip().strip("'")  
return bytes.fromhex(hx)

def find_key_byte_probe(remote: Remote, pos: int) -> int:  
def oracle(block: bytes) -> bytes:  
remote.send_line(block.hex())  
line = remote.read_line()  
c = parse_cipher_line(line)  
remote.read_until(b"message to encrypt: ")  
return c

base = bytearray(16)  
for p in range(256):  
base[pos] = p  
c1 = oracle(bytes(base))  
base[pos] = p ^ COLLISION_DELTA  
c2 = oracle(bytes(base))  
if c1 == c2:  
return p  
raise RuntimeError(f"no collision found for pos={pos}")

def brute_force_key(probes: list[int], c_kk: bytes) -> Optional[bytes]:  
candidates = []  
for pos, p in enumerate(probes):  
if pos == 0:  
a = p ^ ARK_CONST  
b = p ^ ARK_CONST ^ COLLISION_DELTA  
else:  
a = p  
b = p ^ COLLISION_DELTA  
candidates.append((a, b))

for choice_bits in itertools.product([0, 1], repeat=16):  
key_bytes = bytes(candidates[i][choice_bits[i]] for i in range(16))  
if encrypt(key_bytes, key_bytes) == c_kk:  
return key_bytes  
return None

def main() -> int:  
ap = argparse.ArgumentParser()  
ap.add_argument("host", nargs="?", default="52.59.124.14")  
ap.add_argument("port", nargs="?", type=int, default=5103)  
args = ap.parse_args()

r = Remote(args.host, args.port)  
try:  
first_cipher_line = None  
while True:  
line = r.read_line()  
if b"cipher.hex()" in line:  
first_cipher_line = line  
break  
c_kk = parse_cipher_line(first_cipher_line)  
r.read_until(b"message to encrypt: ")

probes: list[int] = []  
for pos in range(16):  
p = find_key_byte_probe(r, pos)  
probes.append(p)  
print(f"[+] pos {pos:02d}: probe=0x{p:02x}")  
sys.stdout.flush()

key = brute_force_key(probes, c_kk)  
if key is None:  
print("[-] key not found (unexpected)")  
return 2  
print(f"[+] key = {key.hex()}")

r.send_line("end")  
r.read_until(b"Can you tell me the key in hex? ")  
r.send_line(key.hex())

r.sock.settimeout(1.0)  
out = bytearray()  
end_by = time.time() + 5.0  
while True:  
try:  
chunk = r.sock.recv(4096)  
if not chunk:  
break  
out.extend(chunk)  
end_by = time.time() + 1.0  
except socket.timeout:  
if time.time() > end_by:  
break  
if out:  
print(out.decode(errors="ignore"), end="")  
return 0  
finally:  
r.close()

if __name__ == "__main__":  
raise SystemExit(main())  
```

## Flag  
`ENO{a1l_cop5_ar3_br0adca5t1ng_w1th_t3tra}`
