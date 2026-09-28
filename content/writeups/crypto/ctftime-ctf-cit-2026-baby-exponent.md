---
title: "Baby Exponent - CTF@CIT 2026"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "hastad", "coppersmith", "low-exponent", "baby", "exponent", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Category: Crypto · Points: 986 · Author: yung"
source:
  name: "CTFtime writeup #40731"
  url: "https://ctftime.org/writeup/40731"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Baby Exponent"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Baby Exponent
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40731>

---
# Baby Exponent — Writeup

\- **Category:** Crypto · **Points:** 986 · **Author:** yung  
\- **Flag:** `CIT{sm4ll_3xp0n3nt_g0_brrr}`

## Given

```text  
n = 3975311104…699223 (800-bit modulus)  
e = 3  
c = 21208016443…080037 (643-bit ciphertext)  
```

## Observation

`c` is only 643 bits; `n` is 800 bits. So `c < n`. For RSA with `e = 3`, if the message `m` is small enough that `m³ < n`, then `c = m³ mod n = m³` exactly — no modular reduction happens — and `m` is just the integer cube root of `c`.

Bit-check: if plaintext is ~215 bits (27 ASCII chars, as the flag turns out to be), then `m³` is ~645 bits. 645 < 800\. ✓ Cube-root attack applies.

## Solve

```python  
def icbrt(n):  
if n < 2: return n  
x = 1 << ((n.bit_length() + 2) // 3)  
while True:  
y = (2*x + n // (x*x)) // 3  
if y >= x: return x  
x = y

m = icbrt(c)  
assert m**3 == c  
print(m.to_bytes((m.bit_length()+7)//8, 'big').decode())  
# -> CIT{sm4ll_3xp0n3nt_g0_brrr}  
```

`m³ == c` holds exactly, so no Håstad-broadcast / Coppersmith needed — plain integer cube root.

## Reproduce

```sh  
python3 scripts/[solve.py](http://solve.py)  
```

## Lesson (what the challenge is teaching)

Using `e = 3` with no padding and a short message is the textbook small-exponent failure mode. Real RSA always pads (OAEP, PKCS#1 v1.5) so `m` gets randomised up near `n`, making `m^e` wrap and `cuberoot(c) ≠ m`. Without padding, any `m` with `m^e < n` leaks immediately.
