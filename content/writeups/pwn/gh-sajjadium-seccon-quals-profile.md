---
title: "profile - SECCON Quals 2018"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "one-gadget", "canary", "aslr", "profile"]
summary: "In SECCON 2018 - profile challenge, there is a buffer overflow vulnerability which leads to overwriting the return address."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2018/Quals/profile/README.md"
ctf:
  name: "SECCON Quals"
  year: 2018
  challenge: "profile"
---

## Source

- **CTF:** SECCON Quals 2018
- **Challenge:** profile
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2018/Quals/profile/README.md>

---
In `SECCON 2018 - profile` challenge, there is a `buffer overflow` vulnerability which leads to overwriting the `return` address. In this challenge, we need to have a good understanding of `string` class's internal memory layout. Using this vulnerability, we can overwrite a string's internal pointer which gives us an `arbitrary read`. We first leak the `canary` value, then leak `read@GOT` address to find `libc` base address, and finally overwrite the return address with `one gadget` to execute `/bin/sh`. This is an interesting `C++` challenge to learn bypassing protections like `NX`, `Canary`, `Partial RELRO`, and `ASLR` in `x86_64` binaries.
