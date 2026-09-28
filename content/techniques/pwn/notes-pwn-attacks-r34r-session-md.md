---
title: "R34R Session (Attacks)"
category: "pwn"
subcategory: "attacks"
type: "technique"
tags: ["my-notes", "personal", "heap", "aslr", "pwndbg", "pwn"]
summary: "Personal note: R34R Session (Attacks)."
source:
  name: "Personal notes"
origin_path: "pwn/Attacks/r34r session.md"
---

# libc leak
```
alias aslr_off='echo 0 | sudo tee /proc/sys/kernel/randomize_va_space'
alias aslr_on='echo 1 | sudo tee /proc/sys/kernel/randomize_va_space'
```

```
pwndbg> aslr on
Change will take effect when the process restarts
ASLR is OFF (read status from process' personality)
```

```
pwndbg> run
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
...
    0x7e61a0d91000     0x7e61a0db3000 r--p    22000      0 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/glibc/libc.so.6
...
```

```
pwndbg> run
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
...
    0x74855d6ab000     0x74855d6cd000 r--p    22000      0 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/glibc/libc.so.6
...
pwndbg>
```

```
pwndbg> got -r
State of the GOT of /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/void:
GOT protection: Partial RELRO | Found 3 GOT entries passing the filter
[0x4031f0] __libc_start_main@GLIBC_2.2.5 -> 0x74855d6cec20 (__libc_start_main) ◂— push r15
[0x4031f8] __gmon_start__ -> 0
[0x404018] read@GLIBC_2.2.5 -> 0x74855d797780 (read) ◂— mov eax, dword ptr fs:[0x18]
```

```
pwndbg> vmmap 0x404018
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x403000           0x404000 r--p     1000   3000 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/void
►         0x404000           0x405000 rw-p     1000   4000 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/void +0x18
    0x74855d6ab000     0x74855d6cd000 r--p    22000      0 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/glibc/libc.so.6
```

```
pwndbg> info files
Symbols from "/home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/void".
Native process:
        Using the running image of child process 158453.
        While running this, GDB does not access memory from...
Local exec file:
        `/home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/void', file type elf64-x86-64.
        Entry point: 0x401040
...
        0x0000000000404030 - 0x0000000000404038 is .bss
```

```
pwndbg> vmmap 0x0000000000404030
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x403000           0x404000 r--p     1000   3000 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/void
►         0x404000           0x405000 rw-p     1000   4000 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/void +0x30
    0x74855d6ab000     0x74855d6cd000 r--p    22000      0 /home/serioton/hackthebox/tryout-ctf/pwn/void/challenge/glibc/libc.so.6
```

---

*From your own notes: `pwn/Attacks/r34r session.md`*
