---
title: "Magical Oracle - L3akCTF 2025"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "prng", "hidden-number-problem", "magical", "oracle", "l3akctf", "l3akctf-2025", "2025", "ctf-writeup"]
summary: "Challenge: Magical Oracle"
source:
  name: "CTFtime writeup #40343"
  url: "https://ctftime.org/writeup/40343"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-07-14-Magical-Oracle-writeup"
ctf:
  name: "L3akCTF 2025"
  year: 2025
  challenge: "Magical Oracle"
---

## Metadata

- **CTF:** L3akCTF 2025
- **Task:** Magical Oracle
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/40343>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-07-14-Magical-Oracle-writeup>

---
![Banner](https://writeups.thebusfactoris1.online/assets/files/magical/image.png)

**Challenge:** Magical Oracle  
**Category:** Cryptography  
**Points:** 436

### Introduction

Ah, the "Magical Oracle." The name itself promised some arcane cryptographic wizardry, and it did not disappoint. When we first connected, we were greeted by a classic setup: a prime `p`, a bunch of parameters, and an oracle that leaked *just enough* information to be interesting.

The core of the problem was a textbook (well, almost) Hidden Number Problem, or HNP. The oracle would take a random number `t`, calculate `(alpha * t) % p` where `alpha` was the secret key, and give us back a value `z` that was *really* close to the real result. Our mission, should we choose to accept it, was to use these slightly-off results to uncover the exact value of `alpha` and use it to decrypt the flag. Easy, right?

### FULL SOLUTION : [Magical Oracle - L3AK-CTF 2025 Write-up](https://writeups.thebusfactoris1.online/posts/2025-07-14-Magical-Oracle-writeup)
