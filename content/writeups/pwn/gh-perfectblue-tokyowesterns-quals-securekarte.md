---
title: "SecureKarte - tokyowesterns quals 2019"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "fastbin", "unsorted-bin", "securekarte", "heap", "binary-exploitation"]
summary: "The bug is that we can modify a freed chunk once."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/tokyowesterns-2019-quals/SecureKarte/README.md"
ctf:
  name: "tokyowesterns quals"
  year: 2019
  challenge: "SecureKarte"
---

## Source

- **CTF:** tokyowesterns quals 2019
- **Challenge:** SecureKarte
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/tokyowesterns-2019-quals/SecureKarte/README.md>

---
# Secure Karte

The bug is that we can modify a freed chunk once. To solve this we can obtain a fake fast chunk in the global buffer to obtain unlimited fastbins fd dupe. We then use unsorted bin attack to place a libc pointer in global buffer, partial overwrite into stdout to obtain leaks. Then we obtain a fast chunk in pointers list using the pointer to the chunk in stdout, clobber lock, then since we now have leaks, we can easily fastbin dupe mallochook and win.
