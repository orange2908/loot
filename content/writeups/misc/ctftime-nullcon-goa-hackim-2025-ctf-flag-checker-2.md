---
title: "flag checker - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "checker", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "enc = [0xF8, 0xA8, 0xB8, 0x21, 0x60, 0x73, 0x90, 0x83, 0x80, 0xC3, 0x9B, 0x80, 0xAB, 0x09, 0x59, 0xD3, 0x21, 0xD3, 0xDB, 0xD8, 0xFB, 0x49, 0x99, 0xE0, 0x79, 0x3C, 0x4C, 0x49, 0x2C, 0x29, 0xCC, 0xD4, 0"
source:
  name: "CTFtime writeup #39971"
  url: "https://ctftime.org/writeup/39971"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BJF4nJUKyx"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "flag checker"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** flag checker
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39971>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BJF4nJUKyx>

---
enc = [0xF8, 0xA8, 0xB8, 0x21, 0x60, 0x73, 0x90, 0x83, 0x80, 0xC3, 0x9B, 0x80, 0xAB, 0x09, 0x59, 0xD3, 0x21, 0xD3, 0xDB, 0xD8, 0xFB, 0x49, 0x99, 0xE0, 0x79, 0x3C, 0x4C, 0x49, 0x2C, 0x29, 0xCC, 0xD4, 0xDC, 0x42] dec = "" for i in range(len(enc)): dec += chr((((((enc[i] << 5) | (enc[i] >> 3)) & 0xFF) - i) & 0xFF) ^ 0x5A) print(dec)

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
