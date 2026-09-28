---
title: "Wild West - justCTF 2024 teaser"
category: "pwn"
subcategory: "pow"
type: "writeup"
tags: ["pwn", "proof-of-work", "wild", "west", "pow", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "io = remote(\"wildwest.nc.jctf.pro\", 1337)"
source:
  name: "CTFtime writeup #39196"
  url: "https://ctftime.org/writeup/39196"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "Wild West"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** Wild West
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39196>

---
```python  
import hashlib

from pwn import remote

io = remote("[wildwest.nc.jctf.pro](http://wildwest.nc.jctf.pro)", 1337)

io.recvuntil(b"prefix: ")  
prefix = io.recvline(keepends=False)

io.recvuntil(b"zero_length: ")  
zero_length = int(io.recvline(keepends=False))

def pow():  
for a in range(32, 127):  
for b in range(32, 127):  
for c in range(32, 127):  
for d in range(32, 127):  
for e in range(32, 127):  
for f in range(32, 127):  
combined = prefix + bytes((a, b, c, d, e, f))  
hash_value = hashlib.sha256(combined).hexdigest()

if hash_value[:zero_length] == "0" * zero_length:  
io.sendlineafter(b"sufix: ", bytes((a, b, c, d, e, f)))  
return

pow()

def kelly(w, l, p):  
q = 1 - p  
ev = p * w + q * -l  
s2 = p * (w**2) + q * (l**2) - (ev**2)  
return ev / s2

i = 0  
while True:  
if i % 30 == 0:  
print(i // 30)  
i += 1  
try:  
io.recvuntil(b"Win: ", timeout=10)  
w = float(io.recvuntil(b",", drop=True))  
io.recvuntil(b"loss: ")  
l = float(io.recvuntil(b",", drop=True))  
io.recvuntil(b"p(win): ")  
p = float(io.recvuntil(b",", drop=True))  
io.recvuntil(b"balane: ")  
bal = int(io.recvline(keepends=False))  
io.sendlineafter(b"bet:", str(int(bal * kelly(w, l, p))).encode())  
except:  
io.interactive()  
```
