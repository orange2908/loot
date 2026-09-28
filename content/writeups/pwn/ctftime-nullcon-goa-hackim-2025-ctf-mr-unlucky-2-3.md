---
title: "mr unlucky - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "prng"
type: "writeup"
tags: ["pwn", "prng", "pwntools", "checksec", "unlucky", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This is an ELF requiring guessing the correct hero out of 20 heros for 50 times."
source:
  name: "CTFtime writeup #39919"
  url: "https://ctftime.org/writeup/39919"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#Mr-Unlucky"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "mr unlucky"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** mr unlucky
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39919>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#Mr-Unlucky>

---
This is an ELF requiring guessing the correct hero out of 20 heros for 50 times. Since it uses the c random with current time as the seed, we can set the seed and predict the exact random number generated and thus the hero.

```python=  
from pwn import *  
import time  
from ctypes import CDLL  
from ctypes.util import find_library  
libc = CDLL(find_library("c"))

# Set up pwntools for the correct architecture  
exe = './mr_unlucky'  
# This will automatically get context arch, bits, os etc  
elf = context.binary = ELF(exe, checksec=False)  
# Change logging level to help with debugging (error/warning/info/debug)  
context.log_level = 'debug'  
context.terminal = "cmd.exe /c start wsl".split()

heroes = [  
"Anti-Mage",  
"Axe",  
"Bane",  
"Bloodseeker",  
"Crystal Maiden",  
"Drow Ranger",  
"Earthshaker",  
"Juggernaut",  
"Mirana",  
"Morphling",  
"Phantom Assassin",  
"Pudge",  
"Shadow Fiend",  
"Sniper",  
"Storm Spirit",  
"Sven",  
"Tiny",  
"Vengeful Spirit",  
"Windranger",  
"Zeus",  
]

io = remote('52.59.124.14', 5021)  
io.recvuntil(b'me guess the names?')  
libc.srand(int(time.time()))  
for _ in range(50):  
name = heroes[libc.rand() % 20]  
io.sendlineafter(b'!!!): ', name.encode())  
print(io.recvall())  
io.close()  
```
