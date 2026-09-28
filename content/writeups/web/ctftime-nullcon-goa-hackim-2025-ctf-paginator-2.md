---
title: "Paginator - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "paginator", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "On going to site there is link to see pages 2-10, there contents of ID 2 to 10 can be seen Checking the source code at /?source tells that there is a SQL injection."
source:
  name: "CTFtime writeup #39983"
  url: "https://ctftime.org/writeup/39983"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BJPcq1LY1g"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39983>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BJPcq1LY1g>

---
On going to site there is link to see pages 2-10, there contents of ID 2 to 10 can be seen Checking the source code at /?source tells that there is a SQL injection. The injection is possible at $max. If we pass max as 1,10 OR 1 it will give us the contents of ID 1 which is FLAG in bas64

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
