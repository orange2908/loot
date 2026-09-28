---
title: "mr unlucky - Nullcon Goa HackIM 2025 CTF"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "binaryninja", "unlucky", "static-analysis", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "First of all, this is what the decompiled main looks like from binary ninja:"
source:
  name: "CTFtime writeup #39948"
  url: "https://ctftime.org/writeup/39948"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "mr unlucky"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** mr unlucky
- **Author team:** QnQSec
- **CTFtime:** <https://ctftime.org/writeup/39948>

---
### Mr Unlucky writeup  
First of all, this is what the decompiled main looks like from binary ninja:  
```c

{  
int64_t fsbase;  
int64_t rax = *(uint64_t*)(fsbase + 0x28);  
init();  
puts("I have always been unlucky. I ca…");  
puts("however, I heard that this tool …");  
puts("YET I CAN'T BEAT IT'S CHALLENGE.…");  
srand(time(nullptr));  
sleep(3);  
puts("Welcome to dota2 hero guesser! Y…");  
  
for (int32_t i = 0; i <= 49; i += 1)  
{  
int32_t rdx_1 = rand() % 20;  
printf("Guess the Dota 2 hero (case sens…");  
char buf[0x1e];  
fgets(&buf, 0x1e, stdin);  
buf[strcspn(&buf, U"\n")] = 0;  
  
if (strcmp(&buf, (&heroes)[(int64_t)rdx_1]))  
{  
printf("Wrong guess! The correct hero wa…", (&heroes)[(int64_t)rdx_1]);  
exit(0);  
/* no return */  
}  
  
printf("%s was right! moving on to the n…", &buf;;  
}  
  
puts("Wow you are one lucky person! fi…");  
print_flag("flag.txt");  
*(uint64_t*)(fsbase + 0x28);  
  
if (rax == *(uint64_t*)(fsbase + 0x28))  
return 0;  
  
__stack_chk_fail();  
/* no return */  
}

```  
The program is really straightforward: it randomizes 49 elements from an array of strings and you have to guess the hero the program chose, if you guess them all correctly, the flag gets printed to `stdout`. How are we supposed to solve it? There is apparently no memory corruption vulnerability, but remember what's the first rule about computers: nothing is really random, so if you know the seed the program uses you can predict all the heros the program will choose. The seed is set with the line `srand(time(nullptr))`, which sets the seed at the current time, which is expressed in seconds.   
So if you execute `time(NULL)` within the first second the result will be the same, and so will our seed.   
The solution is pretty obvious from here:

```python  
import time  
import ctypes  
from pwn import *

heroes = ["Anti-Mage", "Axe", "Bane", "Bloodseeker", "Crystal Maiden", "Drow Ranger", "Earthshaker", "Juggernaut", "Mirana", "Morphling", "Phantom Assassin", "Pudge", "Shadow Fiend", "Sniper", "Storm Spirit", "Sven", "Tiny", "Vengeful Spirit", "Windranger", "Zeus"]

libc = ctypes.CDLL(None)  
def rand():  
return libc.rand()

r = remote("52.59.124.14", 5021)  
# random.seed(int(time.time()))  
libc.srand(int(time.time()))  
time.sleep(1)

for i in range(0x32):  
r.sendline(heroes[rand() % 0x14])

r.interactive()  
```
