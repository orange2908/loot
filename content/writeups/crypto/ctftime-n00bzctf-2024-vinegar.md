---
title: "Vinegar - n00bzCTF 2024"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "vigenere", "vinegar", "classical", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "on this challenge, we were given with ciphertext and a key to decrypt it then after reviewing challenge name again, this one should be vigenere cipher"
source:
  name: "CTFtime writeup #39387"
  url: "https://ctftime.org/writeup/39387"
original_source: "https://github.com/ChickenLoner/Write-Up/blob/main/Unlisted%20Labs/n00bz%20CTF%202024%20Write-up%20(ByTheW4y%20Team).md"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "Vinegar"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** Vinegar
- **Author team:** ByTheW4y
- **CTFtime tags:** crypto, vigenere
- **CTFtime:** <https://ctftime.org/writeup/39387>
- **Original writeup:** <https://github.com/ChickenLoner/Write-Up/blob/main/Unlisted%20Labs/n00bz%20CTF%202024%20Write-up%20(ByTheW4y%20Team).md>

---
![pic1](<https://github.com/ChickenLoner/Write-Up/raw/main/_resources/35f09f305b2a252d3cca36fdf2d074bb.png>)

![pic2](<https://raw.githubusercontent.com/ChickenLoner/Write-Up/main/_resources/5328d339668d636a01fee3228e289614.png>)

on this challenge, we were given with ciphertext and a key to decrypt it then after reviewing challenge name again, this one should be vigenere cipher

![pic3](<https://raw.githubusercontent.com/ChickenLoner/Write-Up/main/_resources/7780ee619553938005aa6d37bc137ac7.png>)

So I went to <https://www.dcode.fr/vigenere-cipher> to decode it and sure enough, this one is vigenere cipher

```  
n00bz{vigenerecipherisfun}  
```
