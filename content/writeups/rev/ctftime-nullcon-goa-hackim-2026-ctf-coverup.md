---
title: "Coverup - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "xor", "base64", "coverup", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40644"
  url: "https://ctftime.org/writeup/40644"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/Coverup/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Coverup"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Coverup
- **Author team:** RootRunners
- **CTFtime tags:** rev
- **CTFtime:** <https://ctftime.org/writeup/40644>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/Coverup/README.md>

---
# Coverup

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Reverse   
**Points:** 89 

**Files:** `encrypted_flag.txt`, `coverage.json`, `encrypt.php`, `generate_challenge.php`, `Dockerfile.public`

## Overview  
The encryptor applies a custom per-byte mapping, XORs with a processed key byte, and applies the same mapping again. The output is returned as `base64(processed) : sha1(processed)`. Branch coverage reveals which key-byte branches executed, so the unordered set of key bytes is leaked.

## Key Observations  
\- The key length is 9 bytes (`generateRandomKey(9)`).  
\- Coverage identifies exactly which `if ($keyChar == chr(n))` branches were hit, yielding the 9 raw key bytes (unordered).  
\- The per-byte mapping converts each raw key byte into the processed key byte used in the XOR.  
\- The same mapping is applied to ciphertext bytes, so each byte has a small set of preimages.

## Solution  
1\. Verify integrity with `sha1(base64_decode(data))`.  
2\. Extract the 9 raw key bytes from coverage and build the per-byte mapping table.  
3\. Transform them into the 9 processed key bytes.  
4\. Compute all valid preimages for each ciphertext byte.  
5\. Brute-force the 9! permutations of the processed key bytes and filter using the `ENO{...}` format and printable output.

## Flag  
`ENO{c0v3r4g3_l34k5_s3cr3t5_really_g00d_you_Kn0w?}`
