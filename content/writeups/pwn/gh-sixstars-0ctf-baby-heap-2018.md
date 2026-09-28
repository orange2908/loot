---
title: "baby heap 2018 - 0ctf 2018"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "fastbin", "off-by-one", "baby", "heap", "binary-exploitation"]
summary: "pwn writeup for \"baby heap 2018\" from 0ctf - techniques: fastbin, off-by-one, baby, heap, binary-exploitation."
source:
  name: "sixstars/ctf"
  url: "https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2018/0ctf/baby-heap-2018/writeup.md"
ctf:
  name: "0ctf"
  year: 2018
  challenge: "baby heap 2018"
---

## Source

- **CTF:** 0ctf 2018
- **Challenge:** baby heap 2018
- **Repository:** [sixstars/ctf](https://github.com/sixstars/ctf)
- **File:** <https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2018/0ctf/baby-heap-2018/writeup.md>

---
Vulnerability: off by one.

1. Use off by one to increase size of one fastbin to smallbin, free it, then we can malloc overlapped chunk.

1. With overlap, we can do fastbin attack to write an arbitrary value to main arena.

1. Do fastbin attack again to malloc a fastbin on main arena (treat the value written in last step as chunk size).

1. Modify the the top in main arena, make it point to the address just before `malloc_hook`.

1. Malloc and modify the `malloc_hook`.

1. Enjoy the shell.
