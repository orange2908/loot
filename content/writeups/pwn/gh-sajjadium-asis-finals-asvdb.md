---
title: "asvdb - ASIS Finals 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "use-after-free", "double-free", "free-hook", "one-gadget", "canary", "aslr", "cache-poisoning", "tcache-poisoning"]
summary: "In this challenge, there is an uninitialized variable vulnerability that leads to double free and use after free (UAF)."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/ASIS/2018/Finals/asvdb/README.md"
ctf:
  name: "ASIS Finals"
  year: 2018
  challenge: "asvdb"
---

## Source

- **CTF:** ASIS Finals 2018
- **Challenge:** asvdb
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/ASIS/2018/Finals/asvdb/README.md>

---
In this challenge, there is an `uninitialized variable` vulnerability that leads to `double free` and `use after free (UAF)`. Using these, we leak a `libc` address to de-randomize `ASLR`, launch `tcache dup` attack, and then put our `fake chunk` address into the `tcache` using `tcache poisoning` attack. As a result, we can force `malloc` to return our `fake chunk` before `__free_hook`, so we can overwrite `__free_hook` with `one gadget`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, `Full RELRO`, and `ASLR` in `x86_64` binaries in presence of `tcache`.
