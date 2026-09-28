---
title: "chainedrsa - defcon 2019"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "coppersmith", "lll", "chainedrsa", "cryptography"]
summary: "Coppersmith attack problem but they use Carmichael lambda totient to generate d instead of Euler phi totient so we wasted a ton of time on this."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/defcon-2019/chainedrsa/README.md"
ctf:
  name: "defcon"
  year: 2019
  challenge: "chainedrsa"
---

## Source

- **CTF:** defcon 2019
- **Challenge:** chainedrsa
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/defcon-2019/chainedrsa/README.md>

---
# chainedrsa

**Category**: Crypto

**Problem description**:

---

Coppersmith attack problem but they use Carmichael lambda totient to generate d instead of Euler phi totient so we wasted a ton of time on this.
I don't think anyone actually understands that complicated LLL shit so rather than to modify the magic LLL code we just use a less sophisticated attack. 
We brute force some bits to make the attack more reliable. This is a stupid trick but oftentimes it is necessary. Solved by sampriti and neptunia.
