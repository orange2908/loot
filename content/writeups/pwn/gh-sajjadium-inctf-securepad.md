---
title: "securepad - InCTF 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "fastbin", "free-hook", "canary", "aslr"]
summary: "In InCTF 2018 - securepad challenge, there is an uninitialized stack variable vulnerability which leads to arbitrary free vulnerability that eventually allows us to launch unsortedbinattack and fastbi"
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/InCTF/2018/securepad/README.md"
ctf:
  name: "InCTF"
  year: 2018
  challenge: "securepad"
---

## Source

- **CTF:** InCTF 2018
- **Challenge:** securepad
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/InCTF/2018/securepad/README.md>

---
In `InCTF 2018 - securepad` challenge, there is an `uninitialized stack variable` vulnerability which leads to `arbitrary free` vulnerability that eventually allows us to launch `unsorted_bin_attack` and `fastbin_dup_attack`. Firstly, we leak a `heap` address and using the `arbitrary free` we get from `uninitialized stack variable` vulnerability, we leak a `main arena` address so we can find `libc` base address. Then, we create a fake chunk before `__free_hook` using `unsorted_bin_attack` and using `fastbin_dup_attack`, we allocate the fake chunk to overwrite `__free_hook` with `system`. This is an interesting `heap exploitation` challenge to learn bypassing protections like `NX`, `Canary`, `Full RELRO`, `PIE`, and `ASLR` in `x86_64` binaries.
