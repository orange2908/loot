---
title: "kleinvieh_2 - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "coppersmith", "small-roots", "rsa", "proof-of-work", "low-exponent", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This challenge provides us with 5 rsa ciphertexts and the corresponding public key."
source:
  name: "CTFtime writeup #39894"
  url: "https://ctftime.org/writeup/39894"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "kleinvieh_2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** kleinvieh_2
- **Author team:** thehackerscrew
- **CTFtime tags:** coppersmith, small_roots
- **CTFtime:** <https://ctftime.org/writeup/39894>

---
This challenge provides us with 5 rsa ciphertexts and the corresponding public key. Each of the 5 ciphertexts correspeonds to a different part of the flag, encrypted with RSA after a different type of "padding" has been applied ot it. To recover the flag we need to find a way to break all 5 methods of padding. Worth noting that the public exponent e is equal to 3, which is known to cause problems.

1st part\  
No padding was applied to the first part. Since `e = 3` and the modulus is so large, we can just takethe cubic root and convert to bytes to decrypt:\  
`ENO{s0m3_0f_th35e_`

2nd part\  
Here instead of m2 (the second part of the flag), what is encrypted is m2\\*r , where r is a known constant. Simply multiply the ciphertext with pow(r, -e, n) to remove this constant and then cube root again, as in part 1: `me1hod5_4ctua1ly_h`

Parts 3-4-5\  
All these have a different type of padding applied. They are all solvable with an application of Coppermsith's. All that's needed is to find the right polynomial and call sagemaths's small_roots . \  
The polynomials for the three parts are:\  
`pol3 = (x*256**(bytelength - 18))**3 - c3`\  
`pol4 = sum([x*256**(18*i) for i in range(28)])**3 - c4`\  
`pol5 = (bytes_to_long(b"\\\x42"*(511 - 18))*256**18 + x)**3 - c5`\  
which produced the final three parts for the flag:\  
`4d_th3_sam3_1de3_t`\  
`h4t_i5_why_1t_i5_j`\  
`u5t_1_ch4ll3nge}`
