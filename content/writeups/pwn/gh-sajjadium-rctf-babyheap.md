---
title: "babyheap - RCTF 2018"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "off-by-one", "malloc-hook", "canary", "aslr", "stack"]
summary: "In this challenge, we are showing how we can leak libc base address and overwrite mallochook using null byte poisoning aka off-by-one overflow aka null byte overflow vulnerability."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/RCTF/2018/babyheap/README.md"
ctf:
  name: "RCTF"
  year: 2018
  challenge: "babyheap"
---

## Source

- **CTF:** RCTF 2018
- **Challenge:** babyheap
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/RCTF/2018/babyheap/README.md>

---
In this challenge, we are showing how we can leak libc base address and overwrite `__malloc_hook` using `null byte poisoning` aka `off-by-one overflow` aka `null byte overflow` vulnerability. Basically, by clearing `PREV_IN_USE` bit in a chunk, we can cause two chunks consolidate and the chunk between them being forgotten.

This is a good challenge for understanding how to exploit `x86_64` binaries with `Full RELRO`, `Canary`, `NX`, `PIE`, and `ASLR` enabled.
