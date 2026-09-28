---
title: "backtrack - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "backtrack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "![ Sign in via Google  ](https://hackmd.io/auth/google)  ![ Sign in via Facebook  ](https://hackmd.io/auth/facebook)  ![ Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter)  ![ Sign in via GitHu"
source:
  name: "CTFtime writeup #39973"
  url: "https://ctftime.org/writeup/39973"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/HJxv2J8Y1l"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "backtrack"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** backtrack
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39973>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/HJxv2J8Y1l>

---
``` i = 0 enc = open("data.bin", "rb") size = len(enc) offset = 4 dec = bytearray() while offset < size: if i == 0: val = int.from_bytes(enc[offset:offset+2], 'little') offset += 2 c = 16 if (val & 1) != 0: v8 = (enc[offset] & 0xf0) << 4 v7 = (enc[offset] & 0xf) + 1 v9 = v8 + enc[(offset + 1)] offset += 2 pos = len(dec) - v9 for j in range(v7): dec.append(dec[pos + i]) else: dec.append(enc[offset]) offset += 1 val >>= 1 c -= 1 print(dec) ```

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
