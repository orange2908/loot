---
title: "memorymaze - dragonctf 2020"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "memorymaze", "miscellaneous", "dragonctf", "perfectblue", "ctf-writeups"]
summary: "misc writeup for \"memorymaze\" from dragonctf - techniques: memorymaze, miscellaneous, dragonctf, perfectblue, ctf-writeups."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/dragonctf/memorymaze/README.md"
ctf:
  name: "dragonctf"
  year: 2020
  challenge: "memorymaze"
---

## Source

- **CTF:** dragonctf 2020
- **Challenge:** memorymaze
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/dragonctf/memorymaze/README.md>

---
Solution script in dickit.py

Solved as team effort.

TLDR, you can choose a file to write to, but if you choose /proc/self/map_files/xxxxxxxx-yyyyyyyy, if the page is mapped, it will give a permission error and if it doesn't exist it will give a nonexistent file error. This lets you construct an oracle to figure out what pages are mapped (and thus the layout of the maze). This lets you find an efficient path through the maze so you can solve it under their path length constraint.
