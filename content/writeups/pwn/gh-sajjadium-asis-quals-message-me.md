---
title: "message me - ASIS Quals 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "fastbin", "use-after-free", "double-free", "malloc-hook", "canary", "aslr"]
summary: "In AsisCTF Quals 2018 - Message Me!"
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/ASIS/2018/Quals/message_me/README.md"
ctf:
  name: "ASIS Quals"
  year: 2018
  challenge: "message me"
---

## Source

- **CTF:** ASIS Quals 2018
- **Challenge:** message me
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/ASIS/2018/Quals/message_me/README.md>

---
In `AsisCTF Quals 2018 - Message Me!` challenge, we leak `libc` base address using a `Use After Free (UAF)` vulnerability. Using the same `Use After Free (UAF)` vulnerability, we overwrite `__malloc_hook` by `overlapping fastbin chunks`. Finally, we trigger `__malloc_hook` using a `Double Free` vulnerability on `fastbins`. This is a good example of `Heap Exploitation` challenge to understand how to hijack control flow in `x86_64` binaries with `Canary`, `NX`, and `ASLR` enabled.
