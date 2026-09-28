---
title: "nuclear_codes - UMDCTF 2026"
category: "misc"
type: "writeup"
tags: ["misc", "nuclear", "codes", "umdctf", "umdctf-2026", "2026", "ctf-writeup"]
summary: "The binary asks for three positive integers a, b, c, checks a > b > c > 0, evaluates a large statically linked MPC/MPFR-style expression at 10000-bit precision, and reads flag.txt only if the check pa"
source:
  name: "CTFtime writeup #40709"
  url: "https://ctftime.org/writeup/40709"
original_source: "https://blog.rawpayload.com/blog/umd-ctf-2026-nuclear-codes-writeup"
ctf:
  name: "UMDCTF 2026"
  year: 2026
  challenge: "nuclear_codes"
---

## Metadata

- **CTF:** UMDCTF 2026
- **Task:** nuclear_codes
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40709>
- **Original writeup:** <https://blog.rawpayload.com/blog/umd-ctf-2026-nuclear-codes-writeup>

---
TL;DR  
The binary asks for three positive integers a, b, c, checks a > b > c > 0, evaluates a large statically linked MPC/MPFR-style expression at 10000-bit precision, and reads flag.txt only if the check passes.

A valid input is:

```  
20260869859883222379931520298326390700152988332214525711323500132179943287700005601210288797153868533207131302477269470450828233936557  
19042526617180316524139256060457587477079898033904404413796747301621619442196095529358289579194164508926431543186710461288793130962534  
16792202595167632657252829598515092665938697948983181195334779924033054964579874761568657321835642556483381729386998074921169204991087  
```
