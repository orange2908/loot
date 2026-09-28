---
title: "txtchecker - seccon quals 2022"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "txtchecker", "cryptography", "seccon-quals", "perfectblue", "ctf-writeups"]
summary: "crypto writeup for \"txtchecker\" from seccon quals - techniques: txtchecker, cryptography, seccon-quals, perfectblue, ctf-writeups."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/seccon-quals-2022/txtchecker/readme.md"
ctf:
  name: "seccon quals"
  year: 2022
  challenge: "txtchecker"
---

## Source

- **CTF:** seccon quals 2022
- **Challenge:** txtchecker
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/seccon-quals-2022/txtchecker/readme.md>

---
* $filepath is not quoted so can inject arbitrary arguments into the file command
* can use `-m /dev/stdin` to allow use to specify a custom magic file:
```
0       string SECCON{A gggg%1000s
>0       string SECCON{A gggg%1000s
>0       string SECCON{A gggg%1000s
...
```
* if the flag matches a bunch of text will be printed and can detect it with timing
* iterate through char by char and get the flag `SECCON{reDo5L1fe}`
