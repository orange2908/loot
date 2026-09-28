---
title: "backdoored_kernel - The Cyber Jawara International 2024"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "canary", "pie", "ghidra", "checksec", "jit", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #39589"
  url: "https://ctftime.org/writeup/39589"
original_source: "https://hyggehalcyon.gitbook.io/page/ctfs/2024/cyber-jawara-international#backdoored_kernel"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "backdoored_kernel"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** backdoored_kernel
- **Author team:** dimas fans club
- **CTFtime:** <https://ctftime.org/writeup/39589>
- **Original writeup:** <https://hyggehalcyon.gitbook.io/page/ctfs/2024/cyber-jawara-international#backdoored_kernel>

---
For the complete documentation index, see [llms.txt](https://hyggehalcyon.gitbook.io/page/llms.txt). This page is also available as [Markdown](https://hyggehalcyon.gitbook.io/page/ctfs/2024/cyber-jawara-international.md).

Team: **swusjask fans club**

Rank: 2nd / 211

Challenge

Category

Points

Solves

Mipsssh

Binary Exploitation

500 pts

2

backdoored_kernel

Binary Exploitation

500 pts

2

Babybrowser

Binary Exploitation

500 pts

0

Cryptology

Binary Exploitation

500 pts

0

## Mipsssh

### Description

> I give you flag so Sssshhhhhhhhhhhhhhhh.... okay? IYKWIM
> 
> `nc 152.42.183.87 10015`
> 
> Author: **Linz**

###  Analysis

we're given a single file called `sssh` let's do basic checks

Copy

```
    └──╼ [★]$ file sssh 
    sssh: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, BuildID[sha1]=04d7856bad89a1366302511296baa20d295e594a, for GNU/Linux 3.2.0, not stripped
    
    └──╼ [★]$ pwn checksec sssh 
        Arch:     mips-32-big
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
```

its a MIPS compiled binary with standard security, note that the binary is also statically linked. 

looking at the decompilation in ghidra, the binary just takes an overflowed input

![](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2F2174594300-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F7LPLfgV3mKZQiLeCJCXU%252Fuploads%252FqhZK5l5W0rp9gpKLPl6C%252Fimage.png%3Falt%3Dmedia%26token%3D22c15f36-dcc0-4238-982e-bbd16dcc940c&width=768&dpr=3&quality=100&sign=1ff6bd3963e0d6e6b3bdc7005de959c3&sv=3)

note that even though checksec result shows the binary has canary, it seems that it doesn't applied to every function.

so this challenge is just basically a ROP challenge in a unfamiliar architecture, that eventually has a goal of calling `execve('/bin/sh', 0, 0)`, since the binary is statically compiled I just assumed `system()` is not an option.

### Familiarizing with MIPS

so first thing first is to figure out what is the syscall instruction equivalent in MIPS, surprise surpise:

[![Logo](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2Fstackoverflow.com%2FContent%2FSites%2Fstackoverflow%2FImg%2Fapple-touch-icon.png%3Fv%3D9168b8ec82a5&width=20&dpr=3&quality=100&sign=9d9c44662b45758b6f6d89f5c709aaca&sv=3)MIPS architecture 'syscall' instructionStack Overflow](https://stackoverflow.com/questions/5938836/mips-architecture-syscall-instruction)

its syscall.

next is what register controls the syscall number, this can be figured out by a quick google search and the answer is `v0`

as for the arguments we can read the documentation and it reveals to be `a0` , `a1` and `a2` for the first 3 arguments.

![](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2F2174594300-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F7LPLfgV3mKZQiLeCJCXU%252Fuploads%252FkKIE4i2XlAbvufUbfljO%252Fimage.png%3Falt%3Dmedia%26token%3D0fcac32f-a4c0-4e44-a1da-d0025a3e7f26&width=768&dpr=3&quality=100&sign=e0d679037169a80127ddb05b93d6492d&sv=3)

for the instructions, I used this cheatsheet for reference for a quick understanding without diving too deep to every single corner of MIPS

[https://uweb.engr.arizona.edu/~ece369/Resources/spim/MIPSReference.pdfuweb.engr.arizona.edu](https://uweb.engr.arizona.edu/~ece369/Resources/spim/MIPSReference.pdf)

### Exploitation

for ROP-ing in MIPS its more similar to ARM rather than x64, this is because the saved return address is stored in the `ra` register instead of in stack (in some occasion the return address does gets stored in the stack)

as for the gadgets, I will summarize their equivalent in x64 terms, I will refer most what I will expalained below from this writeup:

[![Logo](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2Fctftime.org%2Ffavicon.png&width=20&dpr=3&quality=100&sign=8e2e4ccdd5c767c3574c115a6cb24a9a&sv=3)CTFtime.org / 3kCTF-2020 / babym1ps / WriteupCTFtime](https://ctftime.org/writeup/22613)

  * ret / call


the convention for calling a function is usually in the form of `jr/jalr $t9` where `jr/jalr` is the equivalent of the `call` instruction in x64 and `$t9` is where the function address is usually stored. you will see this a lot in the gadgets.

with that in mind a return will be simply `jr/jalr $ra`

  * pop 


there's no directly a `pop` instruction in MIPS, however there is a `lw <register> <offset>($sp)` with `lw` stands for load word to register at a certain offset from the stack pointer. the parentheses signifies to dereference `$sp` as an address, kind of similar to `[rsp-<offset>]` that you might usually see in x64.

  * move


in MIPS theres a lot of equivalent that is able to do this, `move` is a an obvious one, but also `addiu`, `or 0` and other forms as well.

so, a gadget in MIPS ROP typically would involve a load instruction to either `t9` or `ra` and end with `jr/jalr` to either `t9` or `ra`, something like this:

or 

now some of you might notice, if `jalr` or `jr` is the ret and call equivalent instruction, that means its the end of the gadget and why there's additional one instruction also specified after it?

turns out MIPS has this thing called `delay slot` which is best explain by the aforemention writeup:

> the instruction directly after the branch gets executed before the branch/jump gets taken, and also if it's not taken

which means if the next instruction has to be taken into account as it could affect the register you have carefully setup.

now for the actual exploitation, lets first see what registers we have control after the overflow

![](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2F2174594300-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F7LPLfgV3mKZQiLeCJCXU%252Fuploads%252FyNUo63gspDBLeNxJKpYi%252Fimage.png%3Falt%3Dmedia%26token%3D4a173391-3c3d-4f9c-bc6f-409f3011f95f&width=768&dpr=3&quality=100&sign=9b44a459a3a6afe2b719fe342da80b51&sv=3)

first thing I take into care of is the syscall number register, `v0`

I ran ROPGadgets to extract the available gadgets and search for `pop $v0` but found nothing, that can be chained, so I opted to control it with other registers, as we already controled much of the `t[1-7]` registers, I search for `move $v0, $t[1-7]` gadget but found nothing. what I found however is this:

so this means I have to find a `pop $s0` gadget, and there's a convinient one:

next to control `a0` to points to /bin/sh, I used this instruction to move the stack pointer to `a0` and write /bin/sh to said stack offset.

up to this point, `$a2` and `$a1` is still not NULL

![](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2F2174594300-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F7LPLfgV3mKZQiLeCJCXU%252Fuploads%252FjqT1zIDOBb650uCz3SOV%252Fimage.png%3Falt%3Dmedia%26token%3D096615f7-17cb-4af5-ae5e-f21a5c059f08&width=768&dpr=3&quality=100&sign=6cdd26846d7297b2e9d74daff27fd997&sv=3)

to null it I used this little gadget which has nice twist at the end

since `$s0` is once again in our control from the 2nd gadget chain, we can control what goes to `$a2`. next as I run the binary up to this chain, I notice that the `$a1` is also got nullified by the result of said `delay slot` of `move $a1, $fp`, conviniently `$fp` was 0.

![](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2F2174594300-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F7LPLfgV3mKZQiLeCJCXU%252Fuploads%252F0XIQDA9zMe1iDmwYWZBe%252Fimage.png%3Falt%3Dmedia%26token%3Dda30b001-0e00-4c82-beb3-a674418138e6&width=768&dpr=3&quality=100&sign=d77d5dd2aa46744c25cce798697e0302&sv=3)

and so next is just to call syscall and shell should be spawned, here is the exploit being ran againts the remote server:

![](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2F2174594300-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F7LPLfgV3mKZQiLeCJCXU%252Fuploads%252FYjncfe2WjpdlxIjOxHgZ%252Fimage.png%3Falt%3Dmedia%26token%3D8de3c110-be73-4a03-8907-c4603baebab7&width=768&dpr=3&quality=100&sign=ddcd9a1c1df622c74ad789f3e292cb39&sv=3)

here's the full exploit script:

Flag: _**CJ{mipppssssshshshshhs_LINZ_IS_HERE}**_

* * *

##  backdoored_kernel

### Description

> I was learning how to compile a kernel and my friend tampered with a file. Its just 3 lines, right? No way its a backdoor... right?
> 
> `nc 152.42.183.87 10022`
> 
> Author: **Zafirr**

###  Analysis

we're given these files

as the description says, the author compiled the code from source with 3 lines changed specified in `backdoor.patch`

it removes the security check for permission for the character device of mem at `/dev/mem`

quoting from google, character device is:

> Character device files in Linux are a type of special file that allows direct communication between user programs and hardware devices. They are part of the Linux filesystem and play a important role in Linux system administration.

we can pinpoint exactly what function the permission check is removed from by visiting the linux repository

[![Logo](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2Fgithub.com%2Ffluidicon.png&width=20&dpr=3&quality=100&sign=a4396887198604d0312ef416862c609c&sv=3)linux/drivers/char/mem.c at master · torvalds/linuxGitHub](https://github.com/torvalds/linux/blob/master/drivers/char/mem.c)

further search, finds that the function is referenced twice

which by removing the permission check, we basically have full control over the physical memory of the system.

### Exploitation

since we have full control of arbitrary read and write, we can just scan and read the entire memory and find the flag.

apparently this is just a warmup challenge.

here is the exploit being ran againts the remote server:

![](https://hyggehalcyon.gitbook.io/page/~gitbook/image?url=https%3A%2F%2F2174594300-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F7LPLfgV3mKZQiLeCJCXU%252Fuploads%252FfS885uPiFPEJEFypKOju%252Fimage.png%3Falt%3Dmedia%26token%3Dd584f7ce-2fa9-49c6-8095-6d93dc623627&width=768&dpr=3&quality=100&sign=44ee23a530207f0a8261f48f18b92a37&sv=3)

below is the exploit code:

below is the helper script to transfer the exploit to remote:

Flag: _**CJ{8572170a6ebad8e9d9602f7025dbf8cd8f6852c919cad763194c387e2ca2026d}**_

* * *

##  Babybrowser

### Description

> Pls dont 0 day :(, don't bully me :(
> 
> `nc 152.42.183.87 10014`
> 
> Author: **Linz**
> 
> Hint:
> 
> <https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/>
> 
> I mean, that's should be more than enough :D

### Analysis

i will eventually do it

### Exploitation

i will eventually do it

Flag: _**CJ{gg:::__:___::_LINZ_IS_HERE}**_

* * *

##  Cryptology

### Description

> super secure encryption using C++! (again!)
> 
> `nc 68.183.177.211 10020`
> 
> Author: **Zafirr**

###  Analysis

i hate crypto

### Exploitation

i hate crypto, even though its just a layer

Last updated 1 year ago
