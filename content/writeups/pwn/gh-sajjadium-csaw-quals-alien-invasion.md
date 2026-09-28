---
title: "alien invasion - CSAW Quals 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "off-by-one", "canary", "aslr", "alien", "invasion"]
summary: "In CSAW Quals 2018 - alieninvasion challenge, there is an off-by-one (poison-null-byte) vulnerability that allows us to create overlapping chunks situation."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/CSAW/2018/Quals/alien_invasion/README.md"
ctf:
  name: "CSAW Quals"
  year: 2018
  challenge: "alien invasion"
---

## Source

- **CTF:** CSAW Quals 2018
- **Challenge:** alien invasion
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/CSAW/2018/Quals/alien_invasion/README.md>

---
In `CSAW Quals 2018 - alien_invasion` challenge, there is an `off-by-one (poison-null-byte)` vulnerability that allows us to create `overlapping chunks` situation. Basically, we can leak `heap` base address as well as de-randomize `PIE` by manipulating heap chunks and find `libc` base address by leaking `strtoul@GOT`, and finally overwrite `strtoul@GOT` with `system` in order to execute `/bin/sh`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, `PIE`, and `ASLR` in `x86_64` binaries.
