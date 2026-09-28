---
title: "election - SECCON Quals 2017"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "off-by-one", "malloc-hook", "one-gadget", "canary", "aslr"]
summary: "In SECCON 2017 - election challenge, there is an off-by-one (null byte poisoning, null byte overflow) vulnerability that gives us arbitrary write."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2017/Quals/election/README.md"
ctf:
  name: "SECCON Quals"
  year: 2017
  challenge: "election"
---

## Source

- **CTF:** SECCON Quals 2017
- **Challenge:** election
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2017/Quals/election/README.md>

---
In `SECCON 2017 - election` challenge, there is an `off-by-one` (`null byte poisoning`, `null byte overflow`) vulnerability that gives us `arbitrary write`. Using this vulnerability, we can find `heap` base address by manipulating heap chunks and `libc` base address by leaking `read@GOT` address, and finally overwrite `__malloc_hook` with `one gadget` in order to execute `/bin/sh`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, `Full RELRO`, and `ASLR` in `x86_64` binaries.
