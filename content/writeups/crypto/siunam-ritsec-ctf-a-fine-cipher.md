---
title: "A-Fine-Cipher - RITSEC-CTF 2023"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "substitution-cipher", "base32", "a-fine-cipher", "classical", "cryptography"]
summary: "We have intercepted a message from a suspicious group."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/RITSEC-CTF-2023/Crypto/A-Fine-Cipher/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/RITSEC-CTF-2023/Crypto/A-Fine-Cipher/README.md"
ctf:
  name: "RITSEC-CTF"
  year: 2023
  challenge: "A-Fine-Cipher"
---

## Source

- **CTF:** RITSEC-CTF 2023
- **Challenge:** A-Fine-Cipher
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/RITSEC-CTF-2023/Crypto/A-Fine-Cipher/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/RITSEC-CTF-2023/Crypto/A-Fine-Cipher/README.md>

---
# A Fine Cipher

## Overview

- 137 Points / 280 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

We have intercepted a message from a suspicious group. Can you help use break the code and reveal the hidden message?

Encryped Message: `JSNRZHIVJUCVIVFCVYBMVBDRZCXRIVBINCORBCSFHCBINOCRMHBD`

NOTE: Make sure you wrap the flag

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401222057.png)

## Find the flag

Hmm... That message looks like encoded in base32... However, it said "Encryped"...

After fumbling around, I found that the answer is in the challenge's title: "***Afine Cipher***"

> The affine cipher is a type of monoalphabetic substitution cipher, where each letter in an alphabet is mapped to its numeric equivalent, encrypted using a simple mathematical function, and converted back to a letter.

**Then, find a online tool that brute force the encrypted message. I'll use [dcore.fr](https://www.dcode.fr/affine-cipher):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401222245.png)

Found it!

- Flag: `RS{IFYOUAREINTERESTEDCHECKOUTMORECRYTPOCTFSATCRYPTOHACK}`

## Conclusion

What we've learned:

1. Deciphering Affine Cipher
