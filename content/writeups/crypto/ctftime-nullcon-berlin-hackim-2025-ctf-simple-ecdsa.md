---
title: "Simple ECDSA - Nullcon Berlin HackIM 2025 CTF"
category: "crypto"
subcategory: "ecc"
type: "writeup"
tags: ["crypto", "ecc", "ecdsa", "simple", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "I optimised ECDSA. My experiments confirm that it is still a correct signature scheme."
source:
  name: "CTFtime writeup #40402"
  url: "https://ctftime.org/writeup/40402"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "Simple ECDSA"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** Simple ECDSA
- **Author team:** numatrixx
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/40402>

---
# Simple ECDSA — Writeup

## Challenge  
```  
18 Solves  
Simple ECDSA  
449  
I optimised ECDSA. My experiments confirm that it is still a correct signature scheme.

nc 52.59.124.14 5050  
```

We were given a service that claimed to provide an "optimized" version of ECDSA. Our task was to either sign a challenge or recover the flag by forging a valid signature.

\---

## Provided Code  
Two files were given:

\- `[ec.py](http://ec.py)` — basic elliptic curve arithmetic (point addition, doubling, scalar multiplication).  
\- `[chall.py](http://chall.py)` — the server script implementing the signature scheme.

The relevant part of the server’s signing/verification:

```python  
def sign(m, d, k):  
e = H(m)  
r = (k*G).x % n  
s = inverse(k, n) * (e + d) % n  
return r, s

def verify(m, r, s, Q):  
e = H(m)  
R = (e * inverse(s, n)) * G + inverse(s, n) * Q  
return r == R.x % n  
```

\---

## Vulnerability  
This is **not standard ECDSA**.   
In real ECDSA:  
```  
s = k^{-1}( e + d·r ) mod n  
```  
Here, the multiplier `r` was **dropped** — they used:  
```  
s = k^{-1}( e + d ) mod n  
```

Verification becomes:  
```  
R = (e/s)·G + (1/s)·Q  
check r == x(R) mod n  
```

That means we can freely choose `s`, compute `r` accordingly, and produce valid signatures **without the private key**.

\---

## Exploit Strategy  
1\. Connect to the service, parse the public key `Q = d·G`.  
2\. Ask for a challenge string, hash it with **MD5** (as in the code).  
3\. Forge a signature:  
\- Pick `s = 1`.  
\- Compute `R = H(m)·G + Q`.  
\- Set `r = R.x mod n`.  
4\. Send `(r, s)` back to the server.

This is always accepted, since verification holds by construction.

\---

## Exploit Script

```python  
from pwn import remote  
import re, hashlib

# --- elliptic curve implementation omitted for brevity ---  
# (standard P-256 curve, same as [ec.py](http://ec.py))

# connect  
io = remote("52.59.124.14", 5050)

# parse public key  
line = io.recvuntil(b"Choose").decode()  
m = re.search(r"Point\\((\d+),\s*(\d+)\\)", line)  
Qx, Qy = int(m.group(1)), int(m.group(2))  
Q = P(C, Qx, Qy)

# choose option 2  
io.sendline(b"2")  
line = io.recvline().decode()  
chal_hex = re.search(r"([0-9a-f]{64})", line).group(1)  
chal = bytes.fromhex(chal_hex)

# forge  
e = int(hashlib.md5(chal).hexdigest(),16) % n  
R = G*e + Q  
r = R.x % n  
s = 1

# send  
io.sendline(f"{r},{s}".encode())  
print(io.recvall().decode())  
```

\---

## Result  
Running the solver yields:

```  
ENO{1her3_i5_4_lack_0f_r2dund4ncy}  
```

\---

## Lessons  
\- Removing the `r` factor from ECDSA breaks its security completely.  
\- Always stick to standard, reviewed implementations of cryptographic primitives.  
\- Deterministic nonces (RFC 6979) or secure randomness are essential for ECDSA, but even more critical is **not modifying the math**.

\---

**Flag:** `ENO{1her3_i5_4_lack_0f_r2dund4ncy}`
