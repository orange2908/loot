---
title: "inception - ASIS Finals 2018"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "one-gadget", "aslr", "inception", "stack"]
summary: "There is a stack overflow vulnerability in this challenge, by which you can leak read@GOT, find glibc base address, and jump to execve found by one gadget using return oriented programming (ROP) techn"
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/ASIS/2018/Finals/inception/README.md"
ctf:
  name: "ASIS Finals"
  year: 2018
  challenge: "inception"
---

## Source

- **CTF:** ASIS Finals 2018
- **Challenge:** inception
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/ASIS/2018/Finals/inception/README.md>

---
There is a `stack overflow` vulnerability in this challenge, by which you can leak `read@GOT`, find `glibc` base address, and jump to `execve` found by `one gadget` using `return oriented programming (ROP)` technique.

`return-to-csu: A New Method to Bypass 64-bit Linux ASLR` BlackHat talk is a must-read (https://www.blackhat.com/docs/asia-18/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR.pdf).
