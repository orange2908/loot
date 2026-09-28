---
title: "yawn - InCTF 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "fastbin", "off-by-one", "malloc-hook", "one-gadget", "canary", "aslr"]
summary: "In InCTF 2018 - YAWN challenge, there is an off-by-one vulnerability which allows us to overwrite desc pointer with an arbitrary address."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/InCTF/2018/yawn/README.md"
ctf:
  name: "InCTF"
  year: 2018
  challenge: "yawn"
---

## Source

- **CTF:** InCTF 2018
- **Challenge:** yawn
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/InCTF/2018/yawn/README.md>

---
In `InCTF 2018 - YAWN` challenge, there is an `off-by-one` vulnerability which allows us to overwrite `desc` pointer with an arbitrary address. First, we leak `read@GOT` and a `.bss` address to find `libc` and `heap` base addresses, respectively. Then, we can `free` arbitrary `chunks` in the `heap` which allows us to launch `fastbin dup` attack. As a result, we can force `malloc` to return a `fake chunk` before `__malloc_hook`, so we can overwrite `__malloc_hook` with `one gadget`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, `Full RELRO`, and `ASLR` in `x86_64` binaries.
