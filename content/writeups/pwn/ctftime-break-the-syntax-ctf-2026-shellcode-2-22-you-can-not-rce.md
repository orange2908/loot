---
title: "Shellcode: 2.22 You Can (Not) RCE - Break The Syntax CTF 2026"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "xor", "rop", "shellcode", "rce", "break-the-syntax-ctf", "break-the-syntax-ctf-2026", "2026", "ctf-writeup"]
summary: "The program creates an RWX mapping and calls it as shellcode, but the copied bytes are restricted to:"
source:
  name: "CTFtime writeup #40775"
  url: "https://ctftime.org/writeup/40775"
original_source: "https://blog.rawpayload.com/blog/break-the-syntax-ctf-2026-shellcode-2-22-you-can-not-rce-writeup"
ctf:
  name: "Break The Syntax CTF 2026"
  year: 2026
  challenge: "Shellcode: 2.22 You Can (Not) RCE"
---

## Metadata

- **CTF:** Break The Syntax CTF 2026
- **Task:** Shellcode: 2.22 You Can (Not) RCE
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40775>
- **Original writeup:** <https://blog.rawpayload.com/blog/break-the-syntax-ctf-2026-shellcode-2-22-you-can-not-rce-writeup>

---
TL;DR  
The program creates an RWX mapping and calls it as shellcode, but the copied bytes are restricted to:

0x30 0x31 0x33 0x3c  
At first this looks too restrictive for RCE. The useful instruction is:

30 3c 3c xor byte ptr [rsp+rdi], bh  
The program also counts every byte equal to 0x33 in the whole input and sets rbx = 2^count. With exactly 13 bytes equal to 0x33, rbx = 0x2000, so BH = 0x20.

The shellcode call return address is 0x401441. We use the filtered shellcode to flip one bit in that return address:

0x401441 -> 0x401461  
0x401461 is main+1, right after push rbp. This gives recursive re-entry into main/love without unwinding the old stack frames. The overlapping recursive frames let us pre-place fake saved rbp/rip values for a future main frame.

From there the exploit builds:

a puts(addr) leak primitive,  
a libc leak from puts@got,  
a stack leak by abusing load_expression_of_love,  
a final leave; ret pivot into a ROP chain inside the final input buffer,  
system("/bin/sh").  
The final exploit script is [solve.py](http://solve.py).
