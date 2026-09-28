---
title: "secure keymanager - SECCON Quals 2017"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["pwn", "format-string", "heap", "fastbin", "double-free", "canary", "aslr"]
summary: "In this challenge, there is a double free vulnerability by which we can mount the fastbin dup attack to get an arbitrary write into GOT table."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2017/Quals/secure_keymanager/README.md"
ctf:
  name: "SECCON Quals"
  year: 2017
  challenge: "secure keymanager"
---

## Source

- **CTF:** SECCON Quals 2017
- **Challenge:** secure keymanager
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2017/Quals/secure_keymanager/README.md>

---
In this challenge, there is a `double free` vulnerability by which we can mount the `fastbin dup` attack to get an arbitrary write into `GOT` table. Then, using a `format string` attack, we can leak a `libc` address, and finally execute `system("/bin/sh")` by overwriting a `GOT` entry. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, and `ASLR` in `x86_64` binaries.
