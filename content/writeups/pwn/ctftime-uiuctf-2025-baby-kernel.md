---
title: "Baby Kernel - UIUCTF 2025"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["kernel", "pwn", "use-after-free", "kernel-pwn", "baby", "heap", "uiuctf", "uiuctf-2025", "2025", "ctf-writeup"]
summary: "Exploit the UAF by freeing the buffer and reallocating the slab with a ttystruct via /dev/ptmx."
source:
  name: "CTFtime writeup #40357"
  url: "https://ctftime.org/writeup/40357"
original_source: "https://razvan.sh/writeups/baby-kernel-uiuctf/"
ctf:
  name: "UIUCTF 2025"
  year: 2025
  challenge: "Baby Kernel"
---

## Metadata

- **CTF:** UIUCTF 2025
- **Task:** Baby Kernel
- **Author team:** vianu_hack
- **CTFtime tags:** kernel, pwn
- **CTFtime:** <https://ctftime.org/writeup/40357>
- **Original writeup:** <https://razvan.sh/writeups/baby-kernel-uiuctf/>

---
### Exploit summary

Exploit the UAF by freeing the buffer and reallocating the slab with a tty_struct via /dev/ptmx. Leak the kernel base from the ops pointer and the tty address from an internal pointer. Forge a fake ops table in the tty, redirecting ioctl to a mov [rdx], rsi gadget. Use this to overwrite modprobe_path. Trigger modprobe with invalid magic bytes to execute a custom script that reads the flag.

Full writeup link:  
[<https://razvan.sh/writeups/baby-kernel-uiuctf/>](<https://razvan.sh/writeups/baby-kernel-uiuctf/>)
