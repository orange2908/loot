---
title: "Vending Machine - PwnMe CTF Quals 2025"
category: "crypto"
subcategory: "ecdsa"
type: "writeup"
tags: ["crypto", "ecdsa", "vending", "machine", "pwnme-ctf-quals", "pwnme-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "There are 3 vulnerabilities."
source:
  name: "CTFtime writeup #40058"
  url: "https://ctftime.org/writeup/40058"
original_source: "https://github.com/Ectario/articles-and-wu/tree/master/WriteUps/VendingMachine"
ctf:
  name: "PwnMe CTF Quals 2025"
  year: 2025
  challenge: "Vending Machine"
---

## Metadata

- **CTF:** PwnMe CTF Quals 2025
- **Task:** Vending Machine
- **Author team:** PHREAKS 2600
- **CTFtime:** <https://ctftime.org/writeup/40058>
- **Original writeup:** <https://github.com/Ectario/articles-and-wu/tree/master/WriteUps/VendingMachine>

---
# TL;DR

There are 3 vulnerabilities.

\- the hash function in python has a collision for -1 and -2  
\- with the previous vuln the nonce is biased by 7 bits (which are constant but unknown)  
\- we can forge an ECDSA signature from an already known one (we can forge a new pair (r,s) by subtracting the value of s from the order of the curve, which gives us (r,s')) and so we can get 60 signatures to break the scheme

Finally we just need to apply section 4.3 of the following paper to exploit the challenge: <https://eprint.iacr.org/2019/023.pdf>

# Detailed WriteUp

here -> <https://github.com/Ectario/articles-and-wu/tree/master/WriteUps/VendingMachine>
