---
title: "Asterisk-Alloc - tokyowesterns quals 2019"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "tcache", "unsorted-bin", "use-after-free", "double-free", "fsop"]
summary: "The bug is UAF, so we can double free."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/tokyowesterns-2019-quals/Asterisk-Alloc/README.md"
ctf:
  name: "tokyowesterns quals"
  year: 2019
  challenge: "Asterisk-Alloc"
---

## Source

- **CTF:** tokyowesterns quals 2019
- **Challenge:** Asterisk-Alloc
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/tokyowesterns-2019-quals/Asterisk-Alloc/README.md>

---
# Asterisk Alloc

The bug is UAF, so we can double free. However we can only store three chunks at a time, using calloc, realloc, and malloc, and this is leakless. With the double free vulnerability, we can careful obtain overlapping chunks, use unsorted bins fd and bk to spray libc pointers, partial overwrite the libc pointers to point to stdout file structure and malloc hook. Then we obtain a tcache chunk in stdout to clobber it and obtain leaks. Then, we overwrite malloc hook to system and win.
