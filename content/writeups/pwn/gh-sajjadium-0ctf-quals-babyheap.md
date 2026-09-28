---
title: "babyheap - 0CTF Quals 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "fastbin", "double-free", "off-by-one", "malloc-hook", "one-gadget", "canary", "aslr"]
summary: "In 0CTFQuals 2018 - BabyHeap challenge, there is an off-by-one vulnerability that leads to double free vulnerability which allows us to launch fastbin dup attack."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/0CTF/2018/Quals/babyheap/README.md"
ctf:
  name: "0CTF Quals"
  year: 2018
  challenge: "babyheap"
---

## Source

- **CTF:** 0CTF Quals 2018
- **Challenge:** babyheap
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/0CTF/2018/Quals/babyheap/README.md>

---
In `0CTFQuals 2018 - BabyHeap` challenge, there is an `off-by-one` vulnerability that leads to `double free` vulnerability which allows us to launch `fastbin dup` attack. Basically, we can leak a `libc` address to de-randomize `ASLR`, and overwrite `__malloc_hook` with `one gadget` to execute `/bin/sh`. As part of our exploit, we managed to overwrite `top chunk` pointer in the `main arena` which forces `malloc` to return an almost arbitrary memory location on the following allocation. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, `PIE`, `Full RELRO`, and `ASLR` in `x86_64` binaries.
