---
title: "Vinegar - n00bzCTF 2024"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "vigenere", "vinegar", "classical", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "Can you decode this message?"
source:
  name: "CTFtime writeup #39382"
  url: "https://ctftime.org/writeup/39382"
original_source: "https://github.com/Team-Triada/CTF-writeups/blob/main/n00bzCTF/Vinegar-CRYPTO.md"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "Vinegar"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** Vinegar
- **Author team:** Triada
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/39382>
- **Original writeup:** <https://github.com/Team-Triada/CTF-writeups/blob/main/n00bzCTF/Vinegar-CRYPTO.md>

---
# Challenge: Vinegar  
\- **Category:** Crypto  
\- **Points:** 100  
## Challenge Description:  
Can you decode this message?   
The challenge provides an encrypted flag and a key:  
\- **Encrypted flag:** `nmivrxbiaatjvvbcjsf`  
\- **Key:** `secretkey`   
We are tasked with decoding the encrypted message to reveal the flag.  
\---  
## Solution:  
This challenge uses the **Vigenère cipher**, a method of encrypting alphabetic text by using a simple form of polyalphabetic substitution.  
\- Search online for Vigenere cipher decoder and input the enc flag and the key   
\- ![Vigenere cipher](<https://github.com/user-attachments/assets/9bdb7134-610b-4f2a-a220-cce1449d0c87>)

**Result:**  
\- The decrypted message is: **`vigenerecipherisfun`**.

## Flag:  
The flag is: n00bz{vigenerecipherisfun}   
  
\---
