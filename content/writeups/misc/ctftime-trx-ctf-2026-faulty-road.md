---
title: "faulty-road - TRX CTF 2026"
category: "misc"
type: "writeup"
tags: ["misc", "faulty-road", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "The final reliable recovery path was:"
source:
  name: "CTFtime writeup #40718"
  url: "https://ctftime.org/writeup/40718"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-faulty-road-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "faulty-road"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** faulty-road
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40718>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-faulty-road-writeup>

---
The final reliable recovery path was:

Reverse driver.ko and identify where the flag lives in the loaded kernel module.  
Use the unstable physical-page corruption exploit until it drops us into a root shell.  
Do not execute another uploaded ELF after root, because the exploit has already damaged kernel/page-cache state.  
Use BusyBox shell tools to read the loaded module memory through /proc/kcore.  
Extract the string from the live flag symbol in driver.ko's .data section.  
The important loaded-module fact is:

driver.ko:.data + 0x170 == flag  
On the remote instance, /proc/kallsyms exposed the live flag [driver] address after root, and reading that address from /proc/kcore produced the flag.
