---
title: "the shortest crypto chal - UIUCTF 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["aes", "ecb", "shortest", "crypto", "chal", "uiuctf", "uiuctf-2025", "2025", "ctf-writeup"]
summary: "UIUCTF 2025 - Crypto Challenge Writeup"
source:
  name: "CTFtime writeup #40361"
  url: "https://ctftime.org/writeup/40361"
original_source: "https://medium.com/@alinboby/uiuctf-2025-the-shortest-crypto-chal-challenge-writeup-4d62c334659f"
ctf:
  name: "UIUCTF 2025"
  year: 2025
  challenge: "the shortest crypto chal"
---

## Metadata

- **CTF:** UIUCTF 2025
- **Task:** the shortest crypto chal
- **Author team:** bdhxgrp
- **CTFtime:** <https://ctftime.org/writeup/40361>
- **Original writeup:** <https://medium.com/@alinboby/uiuctf-2025-the-shortest-crypto-chal-challenge-writeup-4d62c334659f>

---
UIUCTF 2025 - Crypto Challenge Writeup

I’ve designed the shortest crypto challenge - can you find the flag?  
author: epistemologist  
Files

Download file

? Challenge Overview

We are provided with a Python source file (Download File):

from Crypto.Cipher import AES  
from hashlib import md5  
from secret import a,b,c,d, FLAG  
assert a**4 + b**4 == c**4 + d**4 + 17 and max(a,b,c,d) < 2e4 and AES.new( f"{a*b*c*d}".zfill(16).encode() , AES.MODE_ECB).encrypt(FLAG).hex() == "41593455378fed8c3bd344827a193bde7ec2044a3f7a3ca6fb77448e9de55155"

Solution: 

from Crypto.Cipher import AES  
# Given ciphertext  
ciphertext = bytes.fromhex("41593455378fed8c3bd344827a193bde7ec2044a3f7a3ca6fb77448e9de55155")  
LIMIT = 3000 # Adjust based on available compute resources  
# Step 1: Precompute fourth powers to avoid repeated exponentiation  
fourth = [i**4 for i in range(LIMIT)]  
# Step 2: Build all (c,d) pairs such that c^4 + d^4 = val  
cd_sums = {}  
for c in range(1, LIMIT):  
for d in range(c, LIMIT): # symmetry: d ≥ c  
val = fourth[c] + fourth[d]  
cd_sums[val] = (c, d)  
# Step 3: Try all (a, b) combinations  
for a in range(1, LIMIT):  
for b in range(a, LIMIT):  
lhs = fourth[a] + fourth[b]  
rhs_target = lhs - 17  
if rhs_target in cd_sums:  
c, d = cd_sums[rhs_target]  
product = a * b * c * d  
keystr = str(product).zfill(16)  
if len(keystr) != 16:  
continue # AES key must be exactly 16 bytes  
key = keystr.encode()  
cipher = AES.new(key, AES.MODE_ECB)  
pt = cipher.decrypt(ciphertext)  
try:  
decoded = pt.decode()  
if decoded.startswith("uiuctf{") and decoded.endswith("}"):  
print(f"[+] ? Flag found: {decoded}")  
print(f"[+] ? Key: {keystr}")  
print(f"[+] ? Params: a={a}, b={b}, c={c}, d={d}")  
exit()  
except:  
continue
