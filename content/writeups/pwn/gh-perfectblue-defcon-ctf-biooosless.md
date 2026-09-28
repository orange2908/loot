---
title: "biooosless - defcon ctf 2020"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcode", "side-channel", "biooosless", "binary-exploitation", "defcon-ctf"]
summary: "Tl;dr read from floppy in 32bit protected mode with no BIOS, using PMIO."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/defcon-ctf-2020/biooosless/README.md"
ctf:
  name: "defcon ctf"
  year: 2020
  challenge: "biooosless"
---

## Source

- **CTF:** defcon ctf 2020
- **Challenge:** biooosless
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/defcon-ctf-2020/biooosless/README.md>

---
# Biooosless

Tl;dr read from floppy in 32bit protected mode with no BIOS, using PMIO. Your shellcode gets pasted into seabios.

# Intended solution

Write a floppy disk driver that does DMA. Output the flag using VGA MMIO

# My solution

1. Floppy disk

- Too stupid and lazy to learn about floppy disk, know remote hardware is always QEMU -> hack seabios to log all in/out instructions, copy paste them into shellcode.
- In/out not working -> add usleep() everywhere, shellcode magically starts working
- Final `in` instructions seems to return flag bytes -> Ignore DMA and use completely idiotic solution that works

2. Outputting the flag

- Too stupid and lazy to read docs and figure out VGA -> copy paste QEMU ACPI shutdown.
- Use as timing side channel for time-based blind boolean exfil. Binary search on flag chars
- Side channel is slow and unreliable -> babysit the brute force and guess words manually to speed it up
