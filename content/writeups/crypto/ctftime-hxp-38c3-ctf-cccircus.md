---
title: "cccircus - hxp 38C3 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "polynomials", "field", "sage", "cccircus", "hxp-38c3-ctf", "ctf-writeup"]
summary: "2024-12-15  2026-03-29  About 600 words  3 minutes"
source:
  name: "CTFtime writeup #39756"
  url: "https://ctftime.org/writeup/39756"
original_source: "https://sylvainpelissier.gitlab.io/posts/2024-12-28-hxp-38c3-ctf-circus/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "cccircus"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** cccircus
- **Author team:** Soudure au beurre
- **CTFtime tags:** polynomials, field
- **CTFtime:** <https://ctftime.org/writeup/39756>
- **Original writeup:** <https://sylvainpelissier.gitlab.io/posts/2024-12-28-hxp-38c3-ctf-circus/>

---
# HXP 38C3 CTF Circus and Cccircus

[__Sylvain](https://github.com/sylvainpelissier "Author")

 __2024-12-15  __2026-03-29  __About 600 words  __3 minutes

Contents __

_This is the solution of the “circus” and “cccircus” challenges of[HXP 38C3 CTF](https://2024.ctf.link) 2024\. The challenges were a CRC computed over a 128-bit finite field and raised to a power. The solution is found with two queries allowing to recover the correct root and finally the key is revealed by a linear equation._

### Details

Category: Crypto

Author : yyyyyyy

### Description

#### circus

My friend said CRC is insecure, so I made it better™. Surely it’s safe now!? 🤡

Download:

[circus-626cf2b1fe5d61b5.tar.xz](https://sylvainpelissier.gitlab.io/resources/2024/hxp/circus/circus-626cf2b1fe5d61b5.tar.xz) (13.2 KiB)

Connection (mirrors):

`nc 159.69.25.217 7007`

#### cccircus

Description:

Come on, how much more betterer™ do I have to make CRC for it to become secure?!?? 🎪🐘🦁🔥🤹 Download:

[cccircus-b17dbb48e606a93b.tar.xz](https://sylvainpelissier.gitlab.io/resources/2024/hxp/circus/cccircus-b17dbb48e606a93b.tar.xz) (13.2 KiB)

Connection (mirrors):

`nc 188.245.36.243 7700`

### Solutions

#### circus

We are allowed to interact with the server with the `query` and `solve` commands. After reading the code, the server generate a 32-byte random key $k$ and when the `query` command is invoked, it generates an element of $\mathbb{F}_{2^{128}}$ by converting the bytes of `k || len(msg) || msg` to and element of the field and output this element raised to the power 10. The first thing to remark is the if we take the 10th root of the `query 00` result, we will get 5 possible roots:

__________

```
     1
    2
    3
    4
    5
    6
    7
    8
```

| 

```
    sage:  R.<x> = GF(2)["x"]
    sage:  f = 0x01f3267f571be716d65f11ecb21b86d2e9
    sage:  F.<x> = GF(2^128,modulus=R(f.bits()))
    sage:  # result of query 00
    sage:  p1 = F.from_bytes(bytes.fromhex("4999f946935b4716ca1655dba0dc0a82"))           
    sage:  roots1 = p1.nth_root(10, all=True)
    sage:  len(roots1)
    5
```  
  
---|---  
  
We also remarked that if we query `01` the value before exponentiation equals the same value as for `query 00` plus one. So we can iterate over all the roots until a root in the first set equals a root plus one in the second set:

__________

```
     1
    2
    3
    4
    5
    6
    7
```

| 

```
    sage:  # result of query 01
    sage:  p2 = F.from_bytes(bytes.fromhex("89faa83bffbfba118ae6cbede0d49613"))
    sage:  roots2 = p2.nth_root(10, all=True)
    sage:  for r in roots1:
    ....:     if r + 1 in roots2:
    ....:         break
    ....:
```  
  
---|---  
  
Then we know that we got the correct root. The value $r$ of the root recovered is the key shifted to the left by 16 and with the value `b"\x01\x00"` added which give algebraically: 

$$ r = k \cdot x^{16} + x^8$$

Thus we can recover the value of the key (reduced modulo $f$) with:

__________

```
     1
    2
    3
```

| 

```
    sage: k = (r - F.from_bytes(b"\x01\x00")) / x^16
    sage: k.to_bytes().hex()
    '006862c026326b4bac9476412cb3e30eaf'
```  
  
---|---  
  
Sending this command with the `solve` command gave the flag:

__________

```
     1
    2
    3
    4
    5
    6
    7
```

| 

```
    $ nc 159.69.25.217 7007
    query 00
    4999f946935b4716ca1655dba0dc0a82
    query 01
    89faa83bffbfba118ae6cbede0d49613
    solve 006862c026326b4bac9476412cb3e30eaf
    hxp{1F_y0U_C4n_r34D_tH1s_I_gU3sS_i7_w4s_n0T_s4F3_4fT3r_4lL}
```  
  
---|---  
  
#### cccircus

The only difference with the previous example was that the result was raised to the power 1000000. However, there were still only 5 roots after the 1000000th root:

__________

```
     1
    2
    3
    4
    5
```

| 

```
    sage:  # result of query 00
    sage:  p1 = F.from_bytes(bytes.fromhex("b5df10c9e04bf238e4b671325bcf4a28"))           
    sage:  roots1 = p1.nth_root(1000000, all=True)
    sage:  len(roots1)
    5
```  
  
---|---  
  
Thus the solution was very similar only taking 1000000th roots:

__________

```
     1
    2
    3
    4
    5
    6
    7
```

| 

```
    $ nc 188.245.36.243 7700
    query 00
    5944e61f380b64a407d7bddf62b86310
    query 01
    38de1e7d81a9ba2e169cf311dc7e49d2
    solve 0043bdb374eb3cb0a2bbf29239b13ed072
    hxp{L1f3_1s_4_CiRCuS_4nD_w3_4rE_7he_cL0wNz}
```  
  
---|---  
  
Updated on 2026-03-29 

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)

[Read Markdown](https://sylvainpelissier.gitlab.io/posts/2024-12-28-hxp-38c3-ctf-circus/index.md "Read Markdown")

[__](javascript:void\(0\); "Share on X")[__](javascript:void\(0\); "Share on Facebook")[__](javascript:void\(0\); "Share on 微博")

[Back](javascript:void\(0\);) | [Home](https://sylvainpelissier.gitlab.io/)

[__LakeCTF 2024 Quals - Wild-Signatures](https://sylvainpelissier.gitlab.io/posts/2024-12-09-lakectf-wild-signatures/ "LakeCTF 2024 Quals - Wild-Signatures ")[Google CTF Merkurated __](https://sylvainpelissier.gitlab.io/posts/2025-07-01-google-ctf-merkurated/ "Google CTF Merkurated")
