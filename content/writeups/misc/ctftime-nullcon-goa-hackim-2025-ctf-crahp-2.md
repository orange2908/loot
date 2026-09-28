---
title: "crahp - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "crahp", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Clicking on the link on provided site gave us the Source code."
source:
  name: "CTFtime writeup #39987"
  url: "https://ctftime.org/writeup/39987"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BJ3IFJ8Yye"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "crahp"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** crahp
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39987>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BJ3IFJ8Yye>

---
Clicking on the link on provided site gave us the Source code. In there it asked us to give it a password that is not AdM1nP@assW0rd! and the crc8 and crc16 of the password should match the crc8 and crc16 of provided string, This is case of CRC collision, brute forcing for a string with matching crc8 and crc16 gave us the password. 

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
