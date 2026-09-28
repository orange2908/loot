---
title: "back to roots - UIUCTF 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["leak", "crypto", "aes", "ecb", "back", "roots", "uiuctf", "uiuctf-2025", "2025", "ctf-writeup"]
summary: "I don’t think you can predict my secret number from just its square root - can you prove me wrong?"
source:
  name: "CTFtime writeup #40358"
  url: "https://ctftime.org/writeup/40358"
original_source: "https://medium.com/@alinboby/crypto-challenge-back-to-roots-uiuctf-2025-22fdd1e08fda"
ctf:
  name: "UIUCTF 2025"
  year: 2025
  challenge: "back to roots"
---

## Metadata

- **CTF:** UIUCTF 2025
- **Task:** back to roots
- **Author team:** bdhxgrp
- **CTFtime tags:** leak, crypto, aes
- **CTFtime:** <https://ctftime.org/writeup/40358>
- **Original writeup:** <https://medium.com/@alinboby/crypto-challenge-back-to-roots-uiuctf-2025-22fdd1e08fda>

---
Category: Crypto  
Prompt:

I don’t think you can predict my secret number from just its square root — can you prove me wrong?

You are given:

A Python encryption script ([chal.py](http://chal.py))

from random import randint  
from decimal import Decimal, getcontext  
from hashlib import md5  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad

from secret import FLAG  
K = randint(10**10, 10**11) # 11-digit integer  
print('K', K)  
leak = int(str(Decimal(K).sqrt()).split('.')[-1]) # decimal part of sqrt(K)  
ct = AES.new(  
md5(f"{K}".encode()).digest(),  
AES.MODE_ECB  
).encrypt(pad(FLAG, 16))  
print(f"leak = {leak}")  
print(f"ct = {ct.hex()}")

An output file containing:  
leak = 4336282047950153046404  
ct = 7863c63a4bb2c782eb67f32928a1deceaee0259d096b192976615fba644558b2ef62e48740f7f28da587846a81697745

Your task: Recover the encrypted flag.

We interpret leak as the decimal portion of sqrt(K):  
leak_decimal=leak10len(leak)\text{leak\\_decimal} = \frac{\text{leak}}{10^{\text{len(leak)}}}  
For any possible integer part of sqrt(K) i, construct:  
sqrt_K=i+leak_decimal\text{sqrt\\_K} = i + \text{leak\\_decimal}  
Then:  
K≈(sqrt_K)2K \approx (\text{sqrt\\_K})²  
We try all plausible integer parts for sqrt(K):

Since K is 11 digits, sqrt(K) must be between 10^5 and 3.2*10^5.

For each approximation of K, we try AES decryption and look for a flag starting with uiuctf{.
