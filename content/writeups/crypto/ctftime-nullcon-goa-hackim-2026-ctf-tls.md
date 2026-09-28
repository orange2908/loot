---
title: "TLS - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "cry", "rsa", "aes", "cbc", "proof-of-work", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40652"
  url: "https://ctftime.org/writeup/40652"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/TLS/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "TLS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** TLS
- **Author team:** RootRunners
- **CTFtime tags:** cry
- **CTFtime:** <https://ctftime.org/writeup/40652>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/TLS/README.md>

---
# TLS

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Crypto   
**Points:** 107   
**Service:** `52.59.124.14:5104` 

## Overview  
The service encrypts the flag with AES-CBC and encrypts the AES key with RSA (e=65537). The server acts as a threshold oracle: if the RSA-decrypted key is `>= 2^128` it returns a specific error message, otherwise it proceeds to AES and returns padding errors.

## Key Insight  
RSA is multiplicative: sending `c' = c * s^e mod n` yields decrypted `m' = m * s mod n`. The oracle tells whether `m' < 2^128`. This is a monotone condition for small `s`, so a binary search on `s` recovers the exact boundary and therefore `m`.

## Solution  
1\. Parse `n` and the ciphertext from the server.  
2\. Define the oracle using `c' = c * s^e mod n`.  
3\. Binary search for the largest `s` such that the oracle returns true.  
4\. Compute `m = floor((2^128 - 1) / s_max)`.  
5\. Use `m` as the AES key and decrypt the flag.

## Requirements  
\- Python 3  
\- `cryptography`

## Exploit Script  
```python  
#!/usr/bin/env python3  
import socket  
import struct  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.backends import default_backend

HOST = "52.59.124.14"  
PORT = 5104  
B = 1 << 128  
E = 65537

def recv_until(sock, marker: bytes) -> bytes:  
data = b""  
while marker not in data:  
chunk = sock.recv(4096)  
if not chunk:  
break  
data += chunk  
return data

def parse_banner(sock):  
buf = b""  
while buf.count(b"\n") < 2:  
buf += sock.recv(4096)  
lines = buf.split(b"\n")  
n = int(lines[0].decode().strip())  
cipher_hex = lines[1].decode().strip()  
# drain prompt  
if b"input cipher" not in buf:  
recv_until(sock, b"input cipher")  
return n, bytes.fromhex(cipher_hex)

def build_cipher(enc_msg, iv, enc_key_int):  
enc_key_bytes = enc_key_int.to_bytes((enc_key_int.bit_length() + 7) // 8 or 1, "big")  
L = len(enc_msg)  
return struct.pack(">I", L) + iv + enc_msg + enc_key_bytes

def main():  
s = socket.create_connection((HOST, PORT), timeout=10)  
s.settimeout(5)

n, cipher = parse_banner(s)  
L = struct.unpack(">I", cipher[:4])[0]  
iv = cipher[4:20]  
enc_msg = cipher[20 : 20 + L]  
enc_key = int.from_bytes(cipher[20 + L :], "big")

def oracle(smul: int) -> bool:  
cprime = (enc_key * pow(smul, E, n)) % n  
test = build_cipher(enc_msg, iv, cprime)  
s.sendall(test.hex().encode() + b"\n")  
resp = recv_until(s, b"input cipher")  
text = resp.decode(errors="ignore")  
# True means NOT "something else went wrong"  
return "something else went wrong" not in text

# find upper bound  
low = 1  
high = 1  
while high < B and oracle(high):  
low = high  
high *= 2  
if high > B:  
high = B

# binary search  
while low + 1 < high:  
mid = (low + high) // 2  
if oracle(mid):  
low = mid  
else:  
high = mid

s_max = low  
m = (B - 1) // s_max

key = m.to_bytes(16, "big")  
decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()  
pt = decryptor.update(enc_msg) + decryptor.finalize()  
pad = pt[-1]  
pt = pt[:-pad]

print(pt.decode(errors="ignore"))  
s.sendall(b"exit\n")

if __name__ == "__main__":  
main()  
```

## Flag  
`ENO{Y4y_a_f4ctor1ng_0rac13}`
