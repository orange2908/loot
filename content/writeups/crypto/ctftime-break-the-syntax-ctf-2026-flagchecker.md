---
title: "flagchecker - Break The Syntax CTF 2026"
category: "crypto"
subcategory: "image"
type: "writeup"
tags: ["crypto", "pie", "lsb", "flagchecker", "image", "break-the-syntax-ctf", "break-the-syntax-ctf-2026", "2026", "ctf-writeup"]
summary: "The provided archive contains a stripped Linux ELF binary named flagchecker plus license text files."
source:
  name: "CTFtime writeup #40774"
  url: "https://ctftime.org/writeup/40774"
original_source: "https://blog.rawpayload.com/blog/break-the-syntax-ctf-2026-flagchecker-writeup"
ctf:
  name: "Break The Syntax CTF 2026"
  year: 2026
  challenge: "flagchecker"
---

## Metadata

- **CTF:** Break The Syntax CTF 2026
- **Task:** flagchecker
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40774>
- **Original writeup:** <https://blog.rawpayload.com/blog/break-the-syntax-ctf-2026-flagchecker-writeup>

---
Challenge summary  
The provided archive contains a stripped Linux ELF binary named flagchecker plus license text files. The binary checks one command-line argument and prints correct: <flag> only when the supplied flag satisfies its internal arithmetic check.

Recovered flag:

BtSCTF{ME_T#IHK_M3_U$ED_WRoNGG_L1CENSE11}  
1\. Initial recon  
Unpack the challenge:

unzip bin.zip  
cd bin  
chmod +x flagchecker  
Identify the binary:

file flagchecker  
Result:

flagchecker: ELF 64-bit LSB pie executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f1bae9982f518662d98e511097c56e207c193e31, for GNU/Linux 4.4.0, stripped  
Run it without arguments:

./flagchecker  
Output:

usage: flagcheck <flag>
