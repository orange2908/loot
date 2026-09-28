---
title: "Noob RSA Returns - BITSCTF 2025"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "gcd", "noob", "returns", "bitsctf", "bitsctf-2025", "2025", "ctf-writeup"]
summary: "We are given e, n, ct as in standard RSA and K = (Ap2 - Cp + D)d, where p, d are as in standard RSA and"
source:
  name: "CTFtime writeup #40041"
  url: "https://ctftime.org/writeup/40041"
original_source: "https://gopherhack.com/posts/bitsctf2025-noob-rsa-returns/"
ctf:
  name: "BITSCTF 2025"
  year: 2025
  challenge: "Noob RSA Returns"
---

## Metadata

- **CTF:** BITSCTF 2025
- **Task:** Noob RSA Returns
- **Author team:** GopherHack
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/40041>
- **Original writeup:** <https://gopherhack.com/posts/bitsctf2025-noob-rsa-returns/>

---
### Problem Summary

We are given `e, n, ct` as in standard RSA and `K = (A*p**2 - C*p + D)*d`, where `p, d` are as in standard RSA and  
```py  
C = 0xbaaaaaad  
D = 0xdeadbeef  
A= 0xbaadf00d  
```  
Our goal is to decrypt `ct`.

### Solution

Since there is a factor of `d` in `K`, it's natural to consider what happens when we take \\\\(2^\\{Ke\\}\bmod n\\\\):  
\\\\[\begin\\{aligned\\}  
2^\\{Ke\\} &\equiv 2^\\{(Ap^2 - Cp + D)de\\}\pmod n  
\\\\\\\ &\equiv 2^\\{Ap^2 - Cp + D\\}\pmod n  
\end\\{aligned\\}\\\\]  
We have \\\\(Ap^2 + Cp + D\equiv A - C + D\pmod\\{p - 1\\}\\\\), so  
\\\\[2^\\{Ke\\} \equiv 2^\\{Ap^2 - Cp + D\\} \equiv 2^\\{A - C + D\\}\pmod p.\\\\]  
Hence, \\\\(2^\\{Ke\\} - 2^\\{A - C + D\\}\\\\) has a factor of \\\\(p\\\\), so we can obtain \\\\(p\\\\) by taking  
\\\\[\gcd(2^\\{Ke\\} - 2^\\{A - C + D\\}, n) = p.\\\\]  
From this we derive the prime factorization of \\\\(n\\\\), and standard RSA decryption follows.

Flag: `BITSCTF{I_H0P3_Y0UR3_H4V1NG_FUN_S0_F4R_EHEHEHEHEHO_93A5B675}`

The final solve script can be found [here](<https://gopherhack.com/_astro/solve.CXbNlQH_.py>).
