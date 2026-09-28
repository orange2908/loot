---
title: "mr unlucky - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
type: "writeup"
tags: ["pwn", "unlucky", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "\"Welcome to dota2 hero guesser!"
source:
  name: "CTFtime writeup #39959"
  url: "https://ctftime.org/writeup/39959"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "mr unlucky"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** mr unlucky
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39959>

---
## Pwn / mr_unlucky

* We had to guess the correct heros 50 times consecutively to get the flag  
* The index was calculated using `rand()` function which was seeded using `time(0)` function. 

```C  
v3 = time(0LL);  
srand(v3);  
sleep(3u);  
puts(  
"Welcome to dota2 hero guesser! Your task is to guess the right hero each time to win the challenge and claim the aegis!");  
for ( i = 0; i <= 49; ++i )  
{  
v6 = rand() % 20;  
printf("Guess the Dota 2 hero (case sensitive!!!): ");  
fgets(s, 30, stdin);  
s[strcspn(s, "\n")] = 0;  
if ( strcmp(s, (&heroes)[v6]) )  
{  
printf("Wrong guess! The correct hero was %s.\n", (&heroes)[v6]);  
exit(0);  
}  
printf("%s was right! moving on to the next guess...\n", s);  
}  
```  
#### Solve Script  
```python  
from pwn import *   
import ctypes   
import time   
libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")  
p = process("./mr_unlucky")  
libc.srand(int(time.time()))  
name = [  
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
for i in range(50):  
idx = libc.rand() % 20   
p.sendlineafter("sensitive!!!):", name[idx]) 

p.interactive()  
```
