---
title: "next-level - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "cryptography", "proof-of-work", "low-exponent", "next-level", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "![ Sign in via Google  ](https://hackmd.io/auth/google)  ![ Sign in via Facebook  ](https://hackmd.io/auth/facebook)  ![ Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter)  ![ Sign in via GitHu"
source:
  name: "CTFtime writeup #40011"
  url: "https://ctftime.org/writeup/40011"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/HyFnsyIK1x"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "next-level"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** next-level
- **Author team:** volticks_fanClub
- **CTFtime tags:** cryptography
- **CTFtime:** <https://ctftime.org/writeup/40011>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/HyFnsyIK1x>

---
```python from gmpy2 import iroot from Crypto.Util.number import * # Given values n = 842955733372614455917139215149786367998989408483882136463558684397050826784554405473281404986074268847665022114356876291445365131548244366599468837778869392604574977016160648076231535588793673536845344975989305317758463762079207183948812779114263906518115672167636134526515103825946273073248648502935673944006264386299102933514541941431848389105755893385245141801018951632390644713514409554482089598460289338073545880196262116013551058638687812839058426467147481 c = 178911853582925091074953906180040707693867299041184394859091151823053279374040732087994928027427055516599491017237986483811850621047816908739709787556523375563298051776181108938835938016314409519090707332840179868647993861754529706055629293586699860402875976104999357565613123187491160887851461728095157125430360026065237722011165355477193299183616800218141392989153891385907169749132280406008273086286095580797819646823785791242488773862940145882627972745288524 # Approximate the prime using cube root pp = iroot(n, 3)[0] # Find the exact primes primes = [p for i in range(-10000, 10000) if (p := pp + i) and n % p == 0] assert len(primes) == 3 # Extract primes p, q, r = primes # Compute phi phi = (p-1) * (q-1) * (r-1) # Compute private exponent e = 65537 d = pow(e, -1, phi) # Decrypt message m = pow(c, d, n) print(long_to_bytes(m).decode()) ```

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
