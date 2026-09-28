---
title: "printful - BuckeyeCTF 2025"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["got", "formatstring", "ropchain", "pwn", "rop", "pie", "pwntools", "buckeyectf", "buckeyectf-2025", "2025", "ctf-writeup"]
summary: "\\- find pie leak and calculate pie base based on page bit masking"
source:
  name: "CTFtime writeup #40501"
  url: "https://ctftime.org/writeup/40501"
original_source: "https://vulnx.dev/blog/posts/Buckeye-CTF-2025/"
ctf:
  name: "BuckeyeCTF 2025"
  year: 2025
  challenge: "printful"
---

## Metadata

- **CTF:** BuckeyeCTF 2025
- **Task:** printful
- **Author team:** ResetSec
- **CTFtime tags:** got, formatstring, ropchain, pwn
- **CTFtime:** <https://ctftime.org/writeup/40501>
- **Original writeup:** <https://vulnx.dev/blog/posts/Buckeye-CTF-2025/>

---
TLDR:  
\- dump the stack  
\- find pie leak and calculate pie base based on page bit masking  
\- dump `.rela.plt`, `.dynsym`, and `.dynstr` from the binary using %s arbitrary read  
\- manually construct GOT table  
\- find leaks for known addresses from GOT  
\- use libc database to obtain 2.31  
\- back to stack dump, find libc return address leak and calculate libc base  
\- use saved RBP for stack leak  
\- use all prior information and pwntools to write ROP chain at return address  
\- quit  
\- get shell :D
