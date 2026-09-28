---
title: "mr unlucky - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "prng"
type: "writeup"
tags: ["pwn", "prng", "unlucky", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Just Game PWN using srand() on libc, we can get the same random number with ctypes"
source:
  name: "CTFtime writeup #39901"
  url: "https://ctftime.org/writeup/39901"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "mr unlucky"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** mr unlucky
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39901>

---
Just Game PWN using srand() on libc, we can get the same random number with ctypes

```  
from pwn import *  
from sys import *  
import ctypes  
import time

context.terminal = ["tmux", "splitw", "-h"]  
elf = context.binary = ELF("./mr_unlucky")  
p = process("./mr_unlucky")  
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

HOST = '52.59.124.14'  
PORT = 5021

cmd = """  
b*main  
"""  
if(argv[1] == 'gdb'):  
gdb.attach(p,cmd)  
elif(argv[1] == 'rm'):  
p = remote(HOST,PORT)

LIBC = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

LIBC.srand(LIBC.time(0))

# Sleep for 3 seconds  
sleep(3)  
# List of heroes  
heroes = [  
"Anti-Mage", "Axe", "Bane", "Bloodseeker", "Crystal Maiden",  
"Drow Ranger", "Earthshaker", "Juggernaut", "Mirana", "Morphling",  
"Phantom Assassin", "Pudge", "Shadow Fiend", "Sniper", "Storm Spirit",  
"Sven", "Tiny", "Vengeful Spirit", "Windranger", "Zeus"  
]

for i in range(50):  
v6 = LIBC.rand() % 20  
ans = heroes[v6]  
print(ans, v6)  
p.sendlineafter(b'!): ', ans)

p.interactive()

```
