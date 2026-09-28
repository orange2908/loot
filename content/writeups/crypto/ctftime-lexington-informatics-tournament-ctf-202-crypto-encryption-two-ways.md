---
title: "crypto/encryption two ways - Lexington Informatics Tournament CTF 2025"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["litctf", "rsa", "xor", "lsb", "crypto", "encryption", "ways", "lexington-informatics-tourname", "lexington-informatics-tournament-c", "2025", "ctf-writeup"]
summary: "crypto/encryption two ways | LITCTF 2025 writeup"
source:
  name: "CTFtime writeup #40383"
  url: "https://ctftime.org/writeup/40383"
original_source: "https://medium.com/@alinboby/encryption-two-ways-and-why-it-broke-litctf-write-up-37471e3fb901"
ctf:
  name: "Lexington Informatics Tournament CTF 2025"
  year: 2025
  challenge: "crypto/encryption two ways"
---

## Metadata

- **CTF:** Lexington Informatics Tournament CTF 2025
- **Task:** crypto/encryption two ways
- **Author team:** bdhxgrp
- **CTFtime tags:** litctf
- **CTFtime:** <https://ctftime.org/writeup/40383>
- **Original writeup:** <https://medium.com/@alinboby/encryption-two-ways-and-why-it-broke-litctf-write-up-37471e3fb901>

---
**crypto/encryption two ways | LITCTF 2025 writeup**

We’re getting XOR-leaky values for the same secret (flag) with each RSA prime, plus a normal RSA ciphertext. The generator that produced those values is short enough to read in one breath: it samples large primes p, q, chooses a random-looking flag, prints flag ^ p, flag ^ q, then prints the RSA public key and an RSA encryption of flag.

Connect; parse integers.  
Compute t = A ^ B = p ^ q.  
Factor N given t using the LSB→MSB backtracking described above.  
Recover flag via XOR: flag = A ^ p (or B ^ q).  
If formatting is weird, optionally decrypt RSA by computing d = e^-1 mod φ(N) and m = c^d mod N.  
  
  
Please follow me on Medium to see the details of this solution.
