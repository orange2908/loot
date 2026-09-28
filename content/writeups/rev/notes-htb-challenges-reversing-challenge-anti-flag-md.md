---
title: "Challenge - Anti Flag (Reversing)"
category: "rev"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "pie", "pwntools", "pwndbg", "ghidra", "radare2", "checksec", "rev", "htb-challenges"]
summary: "ptrace() will make sure the program is running inside a debugger"
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Reversing/Challenge - Anti Flag.md"
---

`ptrace()` will make sure the program is running inside a debugger

[https://seblau.github.io/posts/linux-anti-debugging](https://seblau.github.io/posts/linux-anti-debugging)

- `r2` commands :
    - `s main` select main function
    - `pdf` disassemble it
- `gdb` commands :
    - `starti` start the program and break at the first instruction
    - `piebase` get the _pie base (pwndbg)_
    - `breakrva` setup a breakpoint at the piebase address given
- Patching binaries with ghidra
    - [https://materials.rangeforce.com/tutorial/2020/04/12/Patching-Binaries/](https://materials.rangeforce.com/tutorial/2020/04/12/Patching-Binaries/)
    - script used : [https://github.com/schlafwandler/ghidra_SavePatch](https://github.com/schlafwandler/ghidra_SavePatch)
- `context.binary` in pwntools , everytime you run the binary it will be in the right format (x64 , x32 )
- patch a binary with _pwntools_

```
from pwn import *

exe = './patched_true_flag'

elf = context.binary = ELF(exe, checksec=False) 

elf.asm(elf.symbols.ptrace , 'ret') # replace ptrace with ret
elf.save('new_flag') # save the patched binary to a new file
```

Reference : [https://www.youtube.com/watch?v=L-P5mfkyzeo&ab_channel=CryptoCat](https://www.youtube.com/watch?v=L-P5mfkyzeo&ab_channel=CryptoCat)

---

*From your own notes: `HTB Challenges/Reversing/Challenge - Anti Flag.md`*
