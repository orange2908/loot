---
title: "simplegc - C3CTF 2017"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "use-after-free", "canary", "aslr"]
summary: "In 34C3 2017 - SimpleGC challenge, we leak libc base address using a Use After Free (UAF) vulnerability."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/C3CTF/2017/simplegc/README.md"
ctf:
  name: "C3CTF"
  year: 2017
  challenge: "simplegc"
---

## Source

- **CTF:** C3CTF 2017
- **Challenge:** simplegc
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/C3CTF/2017/simplegc/README.md>

---
In `34C3 2017 - SimpleGC` challenge, we leak `libc` base address using a `Use After Free (UAF)` vulnerability. Using the same `Use After Free (UAF)` vulnerability, we overwrite `free@GOT` with `system` address, and eventually spawn a shell. This is a good example of `Heap Exploitation` challenge to understand how to exploit `x86_64` binaries with `Canary`, `NX`, and `ASLR` enabled in presence of `tcache` feature which is enabled in `glibc-2.26`.
