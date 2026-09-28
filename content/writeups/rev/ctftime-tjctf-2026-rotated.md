---
title: "rotated - TJCTF 2026"
category: "rev"
subcategory: "packers"
type: "writeup"
tags: ["rev", "upx", "packer", "base64", "rotated", "packers", "tjctf", "tjctf-2026", "2026", "ctf-writeup"]
summary: "The challenge file was not a valid ELF at first."
source:
  name: "CTFtime writeup #40785"
  url: "https://ctftime.org/writeup/40785"
original_source: "https://blog.rawpayload.com/blog/tjctf-2026-rotated-writeup"
ctf:
  name: "TJCTF 2026"
  year: 2026
  challenge: "rotated"
---

## Metadata

- **CTF:** TJCTF 2026
- **Task:** rotated
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40785>
- **Original writeup:** <https://blog.rawpayload.com/blog/tjctf-2026-rotated-writeup>

---
Summary  
The challenge file was not a valid ELF at first. Every byte was shifted upward by 0x1d; subtracting 0x1d from each byte recovered a valid Linux x86-64 ELF. The recovered ELF was UPX-packed. After unpacking/runtime execution, the real program wrote an obfuscated Bash script to [script.sh](http://script.sh). The script decoded a gzip-compressed base64 payload. That payload printed a decoy message and hid the real flag in a Bash comment as another base64 string.

Overall chain:

-> byte shift decode: byte - 0x1d  
-> valid ELF: chall.dec  
-> UPX-packed executable  
-> writes [script.sh](http://script.sh)  
-> Bash eval of base64 | gzip -c payload  
-> hidden base64 flag in comment  
-> tjctf{b45h_d3bu6_m4573r}
