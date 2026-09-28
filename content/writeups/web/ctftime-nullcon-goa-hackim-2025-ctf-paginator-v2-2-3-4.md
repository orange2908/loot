---
title: "Paginator v2 - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "base64", "paginator", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Just like v1 this one also has SQL injection but this time flag is not in contents of page 1 like last time."
source:
  name: "CTFtime writeup #39965"
  url: "https://ctftime.org/writeup/39965"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/SktjckUtkx"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator v2
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39965>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/SktjckUtkx>

---
Just like v1 this one also has SQL injection but this time flag is not in contents of page 1 like last time. The Following query gave us the flag in base64: ?p=2,1 UNION SELECT * FROM flag

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
