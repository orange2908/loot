---
title: "registration - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "lattice"
type: "writeup"
tags: ["crypto", "lll", "sage", "proof-of-work", "registration", "lattice", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We collect multiple messages and signatures, then find small linear combination of these messages via LLL to forge a signature."
source:
  name: "CTFtime writeup #39926"
  url: "https://ctftime.org/writeup/39926"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#registration"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "registration"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** registration
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39926>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#registration>

---
We collect multiple messages and signatures, then find small linear combination of these messages via LLL to forge a signature.

```python=  
from sage.all import *  
from hashlib import sha256  
from Crypto.Util.number import long_to_bytes, bytes_to_long  
from pwnlib.tubes.remote import remote  
from pwnlib.tubes.process import process

io = remote('52.59.124.14', 5026)  
n = int(io.recvline().decode().strip().split()[-1])  
a = int(io.recvline().decode().strip().split()[-1])  
e = int(io.recvline().decode().strip().split()[-1])

msgs, sigs = [], []  
for _ in range(80):  
print(f'{_ = }')  
io.sendlineafter(b'> ', b'1')  
msg = bytes.fromhex(io.recvline().decode().strip().split()[-1])  
msg = bytes_to_long(sha256(msg).digest())  
sig = int(io.recvline().decode().strip().split()[-1])  
msgs.append(msg)  
sigs.append(sig)  
  
io.sendlineafter(b'> ', b'2')  
msg = bytes.fromhex(io.recvline().decode().strip().split()[-1])  
msg = bytes_to_long(sha256(msg).digest())

L = block_matrix(ZZ, [  
[identity_matrix(len(msgs)), column_matrix(msgs)],  
[0, msg]  
])  
for row in L.LLL():  
if row[-1] != 0:  
continue  
v1 = vector(ZZ, row[:-1])  
v2 = vector(ZZ, msgs)  
val = v1 * v2  
if val not in [-msg, msg]:  
continue  
if val == -msg:  
row = [-int(x) for x in row]  
print(f'{row = }')  
target_sig = prod([pow(x, y, n) for x, y in zip(sigs, row[:-1])])  
target_sig %= n  
print(pow(target_sig, e, n), pow(a, msg, n))  
io.sendlineafter(b': ', str(target_sig).encode())  
io.interactive()  
break

```
