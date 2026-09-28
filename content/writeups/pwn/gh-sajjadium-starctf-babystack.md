---
title: "babystack - StarCTF 2018"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "one-gadget", "canary", "aslr", "babystack"]
summary: "In StarCTF 2018 - babystack challenge, there is a stack overflow vulnerability by which we can leak atol@GOT address to find libc base address, and jump to one gadget in order to execute execve(\"/bin/"
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/StarCTF/2018/babystack/README.md"
ctf:
  name: "StarCTF"
  year: 2018
  challenge: "babystack"
---

## Source

- **CTF:** StarCTF 2018
- **Challenge:** babystack
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/StarCTF/2018/babystack/README.md>

---
In `StarCTF 2018 - babystack` challenge, there is a `stack overflow` vulnerability by which we can leak `atol@GOT` address to find `libc` base address, and jump to `one gadget` in order to execute `execve("/bin/sh")`. The interesting part is replacing the `stack canary` with the correct value in order to replace the `return address` without crashing the program.

Basically, when using `pthread`, the `Thread Local Storage (TLS)` will be located somewhere near the thread stack, so it can be overwritten in case of a `stack overflow` vulnerability. In this challenge, we can replace the `stack_guard` attribute in `TLS` (http://www.openwall.com/lists/oss-security/2018/02/27/5) with an arbitrary value in order to bypass `canary` protection. This is an interesting `ROP` challenge to learn bypassing protections like `NX`, `Canary`, `Full RELRO`, and `ASLR` in `x86_64` binaries.
