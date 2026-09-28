---
title: "children tcache - HITCON 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "double-free", "off-by-one", "malloc-hook", "one-gadget", "canary", "aslr", "cache-poisoning", "tcache-poisoning"]
summary: "In HITCON 2018 - Children Tcache challenge, there is an off-by-one (poison-null-byte) vulnerability which leads to double free and overlapping chunks."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/HITCON/2018/children_tcache/README.md"
ctf:
  name: "HITCON"
  year: 2018
  challenge: "children tcache"
---

## Source

- **CTF:** HITCON 2018
- **Challenge:** children tcache
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/HITCON/2018/children_tcache/README.md>

---
In `HITCON 2018 - Children Tcache` challenge, there is an `off-by-one` (`poison-null-byte`) vulnerability which leads to `double free` and `overlapping chunks`. Using this, we leak a `libc` address to de-randomize `ASLR`, launch `tcache dup` attack, and then put our `fake chunk` address into the `tcache` using `tcache poisoning` attack. As a result, we can force `malloc` to return our `fake chunk` before `__malloc_hook`, so we can overwrite `__malloc_hook` with `one gadget`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `PIE`, `Canary`, `Full RELRO`, and `ASLR` in `x86_64` binaries in presence of `tcache`.
