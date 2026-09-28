---
title: "video player - seccon 2017"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "heap", "one-gadget", "integer-overflow", "video", "player"]
summary: "Firstly, of course, we need to malloc several times to fill the gaps in heap after random malloc and free operations."
source:
  name: "sixstars/ctf"
  url: "https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2017/seccon/video_player/writeup.md"
ctf:
  name: "seccon"
  year: 2017
  challenge: "video player"
---

## Source

- **CTF:** seccon 2017
- **Challenge:** video player
- **Repository:** [sixstars/ctf](https://github.com/sixstars/ctf)
- **File:** <https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2017/seccon/video_player/writeup.md>

---
## Vulnerabilities

1. Leak 1 byte in playing VideoClip or AudioClip.

1. When appending subtitle clip, append length could be very large to cause integer overflow in `this->length + append_length`.

## Exploit

Firstly, of course, we need to malloc several times to fill the gaps in heap after random malloc and free operations.

For leaking, seems any bug is ok to leak heap addresss and libc address.

The second bug leads to heap buffer overflow, thus we can overwrite vtable of a clip.
One gadget seems not usable.
So we use the gadget in `setcontext` to call `system("/bin/sh")`.
