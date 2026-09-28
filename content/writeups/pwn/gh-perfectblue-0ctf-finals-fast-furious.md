---
title: "Fast&Furious - 0ctf finals 2019"
category: "pwn"
subcategory: "kernel"
type: "writeup"
tags: ["pwn", "kernel-pwn", "kernel-rop", "fast", "furious", "kernel"]
summary: "pwn writeup for \"Fast&Furious\" from 0ctf finals - techniques: kernel-pwn, kernel-rop, fast, furious, kernel."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/0ctf-finals-2019/Fast%26Furious/README.md"
ctf:
  name: "0ctf finals"
  year: 2019
  challenge: "Fast&Furious"
---

## Source

- **CTF:** 0ctf finals 2019
- **Challenge:** Fast&Furious
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/0ctf-finals-2019/Fast%26Furious/README.md>

---
# Fast&Furious
**Category**: Pwn

250 Points

10 Solves

---

Full write-up coming soon. For now please refer to [hax.c](https://raw.githubusercontent.com/perfectblue/ctf-writeups/db9b964bf35c210567ea508383e91a9c423adaee/2019/0ctf-finals-2019/Fast&Furious/hax.c).
It's a lot like the [Blazeme](https://raw.githubusercontent.com/perfectblue/ctf-writeups/db9b964bf35c210567ea508383e91a9c423adaee/2019/blazectf-2018/blazeme-420) challenge from Blazectf 2018, but with SMEP and KPTI. That makes our life more tricky since we cannot return directly to userland: even if we disable SMEP, under KPTI the kernel page table has all user pages marked as NX. Instead we use a ropchain to `commit_creds` then return to the KTPI exit trampoline that swaps CR3 properly. If we don't swap CR3 back to the userland page table we will double fault when we try to step on the first userland instruction after returning.

Another less elegant option is to simply chmod the flag then hang in the kernel, then view the flag on a different core. See [voidexp.c](https://raw.githubusercontent.com/perfectblue/ctf-writeups/db9b964bf35c210567ea508383e91a9c423adaee/2019/0ctf-finals-2019/Fast&Furious/voidexp.c) for this.

Solved as group effort by VoidMercy, Jazzy, cts, theKidOfArcania, and jonathanj
