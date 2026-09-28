---
title: "video player - SECCON Quals 2017"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "fastbin", "use-after-free", "malloc-hook", "one-gadget", "canary", "aslr"]
summary: "In SECCON 2017 - videoplayer challenge, there is a Use After Free (UAF) vulnerability by which we can mount fastbin attack to create overlapping chunks."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2017/Quals/video_player/README.md"
ctf:
  name: "SECCON Quals"
  year: 2017
  challenge: "video player"
---

## Source

- **CTF:** SECCON Quals 2017
- **Challenge:** video player
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/SECCON/2017/Quals/video_player/README.md>

---
In `SECCON 2017 - video_player` challenge, there is a `Use After Free (UAF)` vulnerability by which we can mount `fastbin attack` to create `overlapping chunks`. Using this technique, we can leak a heap address to figure out the layout of chunks and then find `libc` base address by leaking `read@GOT`. Finally, we can overwrite `__malloc_hook` with `one gadget` in order to execute `/bin/sh`. This is an interesting `heap exploitation` challenge in `C++` programs where we can learn about `vtable` (and `virtual calls`) as well as bypassing protections like `NX`, `Canary`, and `ASLR` in `x86_64` binaries.
