---
title: "bfail - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "bfail", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Bfail Going to /source in provided website gave us the code."
source:
  name: "CTFtime writeup #39978"
  url: "https://ctftime.org/writeup/39978"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/HJMdK1LtJe"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "bfail"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** bfail
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39978>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/HJMdK1LtJe>

---
Bfail Going to /source in provided website gave us the code. From there we got the username as admin and first 71 bytes of bcrypt password. Bcrypt ignores the password above 72 bytes, so we need to brute force 1 btye and we get the password. 

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
