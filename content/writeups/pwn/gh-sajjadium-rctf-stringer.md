---
title: "stringer - RCTF 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "fastbin", "double-free", "off-by-one", "malloc-hook", "canary", "aslr"]
summary: "RCTF 2018 - stringer challenge contains off-by-one and double free vulnerabilities."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/RCTF/2018/stringer/README.md"
ctf:
  name: "RCTF"
  year: 2018
  challenge: "stringer"
---

## Source

- **CTF:** RCTF 2018
- **Challenge:** stringer
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/RCTF/2018/stringer/README.md>

---
`RCTF 2018 - stringer` challenge contains `off-by-one` and `double free` vulnerabilities. Lesson learned is that if the chunk being allocated is `MMAPED`, the content will not be zero out when using `calloc`.

So, by using `off-by-one` attack, we can set `IS_MMAPED` bit of the target chunk in order to leak a libc address, and then launch the `fastbin attack` (https://github.com/shellphish/how2heap/blob/master/fastbin_dup_into_stack.c) by using `double free` vulnerability in order to overwrite `__malloc_hook`.

This is a good challenge to understand how to exploit `x86_64` binaries with `Full RELRO`, `Canary`, `NX`, `PIE`, and `ASLR` enabled.
