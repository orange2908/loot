---
title: "pwn02 - WhiteHat Quals 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "off-by-one", "canary", "aslr"]
summary: "In WhiteHat Grand Prix 2018 Quals - pwn02 (BookStore) challenge, there is a null byte poisoning aka off-by-one overflow aka null byte overflow vulnerability."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/WhiteHat/2018/Quals/pwn02/README.md"
ctf:
  name: "WhiteHat Quals"
  year: 2018
  challenge: "pwn02"
---

## Source

- **CTF:** WhiteHat Quals 2018
- **Challenge:** pwn02
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/WhiteHat/2018/Quals/pwn02/README.md>

---
In `WhiteHat Grand Prix 2018 Quals - pwn02 (BookStore)` challenge, there is a `null byte poisoning` aka `off-by-one overflow` aka `null byte overflow` vulnerability. Using this vulnerability, we can create the `overlapping chunks` situation (by zeroing out PREV_INUSE bit), which enables us to leak libc addresses and overwrite a sensitive function pointer with `system` address (spawn `/bin/sh`).

This is a good example of `Heap Exploitation` challenge to understand how to exploit `x86_64` binaries with `Canary`, `Full RELRO`, `FORTIFY`, `NX`, and `ASLR` enabled in presence of `tcache` in `glibc-2.27`.
