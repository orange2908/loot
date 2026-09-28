---
title: "super marimo - Codegate Quals 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "one-gadget", "canary", "aslr", "super", "marimo"]
summary: "In CodeGate 2018 - SuperMarimo challenge, there is a heap overflow vulnerability by which we can leak malloc@GOT address in order to find libc base address."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/Codegate/2018/Quals/super_marimo/README.md"
ctf:
  name: "Codegate Quals"
  year: 2018
  challenge: "super marimo"
---

## Source

- **CTF:** Codegate Quals 2018
- **Challenge:** super marimo
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/Codegate/2018/Quals/super_marimo/README.md>

---
In `CodeGate 2018 - SuperMarimo` challenge, there is a `heap overflow` vulnerability by which we can leak `malloc@GOT` address in order to find `libc` base address. Using the same vulnerability, we can overwrite `malloc@GOT` (since `Full RELRO` is not enabled) with `One Gadget` address to execute `execve("/bin/sh")`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, and `ASLR` in `x86_64` binaries.
