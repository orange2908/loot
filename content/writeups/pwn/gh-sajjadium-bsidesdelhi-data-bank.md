---
title: "data bank - BSidesDelhi 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "use-after-free", "malloc-hook", "one-gadget", "canary", "aslr", "cache-poisoning", "tcache-poisoning"]
summary: "In BSidesDelhi 2018 - databank challenge, there is a use after free (UAF) vulnerability which leads to tcache poisoning."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/BSidesDelhi/2018/data_bank/README.md"
ctf:
  name: "BSidesDelhi"
  year: 2018
  challenge: "data bank"
---

## Source

- **CTF:** BSidesDelhi 2018
- **Challenge:** data bank
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/BSidesDelhi/2018/data_bank/README.md>

---
In `BSidesDelhi 2018 - data_bank` challenge, there is a `use after free (UAF)` vulnerability which leads to `tcache poisoning`. Using this, we leak a `libc` address to de-randomize `ASLR`, and then put our `fake chunk` address into the `tcache` bin using `tcache poisoning` attack. As a result, we can force `malloc` to return our `fake chunk` before `__malloc_hook`, so we can overwrite `__malloc_hook` with `one gadget`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `PIE`, `Canary`, `Full RELRO`, and `ASLR` in `x86_64` binaries in presence of `tcache`.
