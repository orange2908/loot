---
title: "Going in circles - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["crypto", "cry", "chinese-remainder", "radare2", "going", "circles", "number-theory", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40654"
  url: "https://ctftime.org/writeup/40654"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Going_in_circles/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Going in circles"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Going in circles
- **Author team:** RootRunners
- **CTFtime tags:** cry
- **CTFtime:** <https://ctftime.org/writeup/40654>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Going_in_circles/README.md>

---
# Going in Circles

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Crypto   
**Points:** 50   
**Service:** `52.59.124.14:5100` 

## Overview  
The service prints `reduce(flag, f)` for a random 32-bit polynomial `f`. This reduction is exactly a CRC, so each output gives a congruence of the flag polynomial modulo `f`.

## Key Insight  
In GF(2)[x], each sample gives `flag = r (mod f)`. With enough coprime random moduli, we can combine them using the Chinese Remainder Theorem over GF(2)[x] and recover the full polynomial (the flag).

## Solution  
1\. Open many connections and collect `(r, f)` pairs.  
2\. Implement polynomial arithmetic and CRT over GF(2)[x].  
3\. Merge congruences until the modulus degree exceeds the flag length.  
4\. Convert the polynomial to bytes and locate `ENO{...}`.

## Exploit Script  
```python  
#!/usr/bin/env python3  
import socket

HOST = "52.59.124.14"  
PORT = 5100

def get_pair():  
s = socket.create_connection((HOST, PORT), timeout=5)  
data = s.recv(4096).decode().strip()  
s.close()  
parts = data.split()  
if len(parts) < 2:  
return None  
r, f = map(int, parts[:2])  
return r, f

def deg(p):  
return p.bit_length() - 1

def poly_mul(a, b):  
res = 0  
while b:  
if b & 1:  
res ^= a  
b >>= 1  
a <<= 1  
return res

def poly_mod(a, mod):  
if mod == 0:  
return a  
mdeg = deg(mod)  
while a.bit_length() - 1 >= mdeg:  
shift = a.bit_length() - 1 - mdeg  
a ^= mod << shift  
return a

def poly_divmod(a, b):  
q = 0  
r = a  
bdeg = deg(b)  
while r and deg(r) >= bdeg:  
shift = deg(r) - bdeg  
q ^= 1 << shift  
r ^= b << shift  
return q, r

def poly_gcdext(a, b):  
x0, y0 = 1, 0  
x1, y1 = 0, 1  
while b:  
q, r = poly_divmod(a, b)  
a, b = b, r  
x0, x1 = x1, x0 ^ poly_mul(q, x1)  
y0, y1 = y1, y0 ^ poly_mul(q, y1)  
return a, x0, y0

def poly_inv(a, mod):  
g, x, _ = poly_gcdext(a, mod)  
if g != 1:  
return None  
return poly_mod(x, mod)

def crt(r1, m1, r2, m2):  
r1m2 = poly_mod(r1, m2)  
t = r2 ^ r1m2  
inv = poly_inv(poly_mod(m1, m2), m2)  
if inv is None:  
return None, None  
t = poly_mod(poly_mul(t, inv), m2)  
x = r1 ^ poly_mul(m1, t)  
m = poly_mul(m1, m2)  
return x, m

def main():  
r = None  
m = None  
for _ in range(400):  
pair = get_pair()  
if pair is None:  
continue  
r2, m2 = pair  
if r is None:  
r, m = r2, m2  
else:  
x, mm = crt(r, m, r2, m2)  
if x is None:  
continue  
r, m = x, mm  
blen = (r.bit_length() + 7) // 8  
b = r.to_bytes(blen, "big")  
if b"ENO{" in b:  
print(b.decode(errors="ignore"))  
return  
print("not found")

if __name__ == "__main__":  
main()  
```

## Flag  
`ENO{CRC_is_just_some_modular_remainder}`
