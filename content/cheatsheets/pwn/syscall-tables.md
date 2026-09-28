---
title: "Syscall Tables - x86, x86-64, ARM32, AArch64, MIPS"
category: pwn
subcategory: reference
type: reference
tags: [syscall, syscall-table, int-80, execve, mmap, mprotect, openat, dup2, socket, exit, calling-convention, x86, x86-64, arm, aarch64, mips, x32-abi, seccomp, shellcode, pwntools]
summary: "Syscall numbers that matter in pwn for x86 (int 0x80), x86-64, and the generic tables, plus the register calling convention for five architectures."
tools: [pwntools, ausyscall, seccomp-tools, gdb]
related: [shellcode-cheatsheet, shellcode-crafting, shellcode-seccomp-orw, shellcode-arm-mips, rop-static-binary, rop-srop, rop-gadgets-cheatsheet]
---

## Verify locally before you trust any table

Syscall numbers are per-architecture and occasionally per-kernel. Confirm on the
target rather than trusting a printed table:

```bash
# Authoritative: the kernel headers on the machine
grep -rn '__NR_execve' /usr/include/asm/unistd_64.h
grep -rn '__NR_execve' /usr/include/asm/unistd_32.h
grep -rn '__NR_execve' /usr/include/asm-generic/unistd.h      # aarch64, riscv, ...
grep -rn 'execve' /usr/include/x86_64-linux-gnu/asm/unistd_64.h

# Kernel source layout (x86 master table)
sed -n '1,40p' arch/x86/entry/syscalls/syscall_64.tbl
sed -n '1,40p' arch/x86/entry/syscalls/syscall_32.tbl
sed -n '1,40p' arch/arm/tools/syscall.tbl
sed -n '1,40p' arch/mips/kernel/syscalls/syscall_o32.tbl

# auditd helper
ausyscall --dump
ausyscall --dump | grep -w execve
ausyscall x86_64 execve
ausyscall i386 59
```

```python
# pwntools carries the tables for every arch it supports
from pwn import *
context.arch = 'amd64'; print(constants.SYS_execve)      # 59
context.arch = 'i386';  print(constants.SYS_execve)      # 11
context.arch = 'arm';   print(constants.SYS_execve)
context.arch = 'aarch64'; print(constants.SYS_execve)    # 221
context.arch = 'mips';  print(constants.SYS_execve)      # 4011
print(constants.O_RDONLY, constants.PROT_READ | PROT_WRITE | PROT_EXEC)
print(constants.AT_FDCWD)
```

---

## Calling conventions

### x86-64 Linux (syscall)

```text
instruction : syscall            (0f 05)
number      : rax
args        : rdi  rsi  rdx  r10  r8  r9        <-- NOTE r10, NOT rcx
return      : rax                (negative = -errno, i.e. 0xffff_ffff_ffff_ffxx)
clobbered   : rcx (return addr), r11 (rflags)
preserved   : rbx rbp rsp r12 r13 r14 r15
```

### x86-64 Linux (userland function calls, System V AMD64 ABI)

```text
args        : rdi  rsi  rdx  rcx  r8  r9, then the stack (right to left)
return      : rax  (rdx:rax for 128-bit)
float args  : xmm0-xmm7
varargs     : al = number of vector registers used (set al=0 for printf-style calls)
alignment   : rsp MUST be 16-byte aligned AT the call instruction, so rsp % 16 == 8
              on entry to the callee. Violating this crashes glibc's movaps.
red zone    : 128 bytes below rsp are scratch in leaf functions
```

### x86 (i386) Linux (int 0x80)

```text
instruction : int 0x80           (cd 80)     always available, even under a 64-bit kernel
              sysenter           (0f 34)     needs a valid frame; normally via __kernel_vsyscall
number      : eax
args        : ebx  ecx  edx  esi  edi  ebp    (6 args max)
return      : eax
```

### x86 (i386) userland function calls (cdecl)

```text
args        : all on the stack, pushed right to left
return      : eax
cleanup     : CALLER pops the arguments
             -> a ROP chain calling f(a, b) looks like
                [f][ret_addr_or_pop2_gadget][a][b]
stdcall/fastcall exist on Windows; Linux CTF binaries are effectively always cdecl
(except -mregparm builds, where the first args are in eax, edx, ecx).
```

### x32 ABI (32-bit pointers inside a 64-bit process)

```text
instruction : syscall
number      : rax = 0x40000000 | nr          (__X32_SYSCALL_BIT)
args        : same registers as x86-64
Use: a seccomp filter that only checks the plain 64-bit numbers can often be
bypassed by invoking the same call with the 0x40000000 bit set, because the
filter's `nr` comparison no longer matches. A correctly written filter checks
`arch` (AUDIT_ARCH_X86_64) and rejects nr >= 0x40000000.
```

### ARM32 (EABI)

```text
instruction : svc #0             (ef 00 00 00 in ARM mode, df 00 in Thumb)
number      : r7
args        : r0  r1  r2  r3  r4  r5
return      : r0
OABI legacy : swi 0x900000+nr    (number encoded in the instruction, r7 unused)
Thumb       : set bit 0 of any target address to enter Thumb; `bx` honours it
function ABI: args r0-r3 then stack; return r0; return address in lr (r14)
             -> the "saved return address" only reaches the stack when the
                prologue does `push {..., lr}`
```

### AArch64

```text
instruction : svc #0             (01 00 00 d4)
number      : x8
args        : x0  x1  x2  x3  x4  x5
return      : x0
function ABI: args x0-x7 then stack; return x0; return address in x30 (lr)
             `ret` == `br x30`, so ROP needs a gadget that reloads x30,
             typically  ldp x29, x30, [sp], #N ; ret
no `open`, no `dup2`: the generic table only has openat(56) and dup3(24)
```

### MIPS (o32)

```text
instruction : syscall            (0c 00 00 00 big endian)
number      : $v0   (o32 numbers start at 4000)
args        : $a0 $a1 $a2 $a3, further args on the stack at 16($sp)...
return      : $v0, error flag in $a3 (a3 != 0 means $v0 holds errno)
function ABI: args $a0-$a3; return $v0; return address in $ra ($31)
DELAY SLOT  : the instruction AFTER every branch/jump executes BEFORE the jump
              lands. Every gadget must account for it.
$t9         : PIC calls must set $t9 to the callee address before `jalr $t9`
n32 base = 6000, n64 base = 5000
```

---

## x86-64 (`/usr/include/asm/unistd_64.h`)

| nr | name | rdi | rsi | rdx |
|---:|------|-----|-----|-----|
| 0 | read | fd | buf | count |
| 1 | write | fd | buf | count |
| 2 | open | pathname | flags | mode |
| 3 | close | fd | | |
| 5 | fstat | fd | statbuf | |
| 8 | lseek | fd | offset | whence |
| 9 | mmap | addr | length | prot (r10=flags, r8=fd, r9=off) |
| 10 | mprotect | addr | len | prot |
| 11 | munmap | addr | len | |
| 12 | brk | addr | | |
| 15 | rt_sigreturn | (restores the whole sigcontext from the stack) | | |
| 16 | ioctl | fd | request | arg |
| 21 | access | pathname | mode | |
| 22 | pipe | pipefd[2] | | |
| 32 | dup | oldfd | | |
| 33 | dup2 | oldfd | newfd | |
| 34 | pause | | | |
| 35 | nanosleep | req | rem | |
| 37 | alarm | seconds | | |
| 39 | getpid | | | |
| 40 | sendfile | out_fd | in_fd | offset (r10=count) |
| 41 | socket | domain | type | protocol |
| 42 | connect | sockfd | addr | addrlen |
| 43 | accept | sockfd | addr | addrlen |
| 44 | sendto | sockfd | buf | len |
| 45 | recvfrom | sockfd | buf | len |
| 49 | bind | sockfd | addr | addrlen |
| 50 | listen | sockfd | backlog | |
| 54 | setsockopt | sockfd | level | optname |
| 56 | clone | flags | stack | parent_tid |
| 57 | fork | | | |
| 58 | vfork | | | |
| 59 | execve | pathname | argv | envp |
| 60 | exit | status | | |
| 61 | wait4 | pid | wstatus | options |
| 62 | kill | pid | sig | |
| 63 | uname | buf | | |
| 72 | fcntl | fd | cmd | arg |
| 76 | truncate | path | length | |
| 78 | getdents | fd | dirp | count |
| 79 | getcwd | buf | size | |
| 80 | chdir | path | | |
| 83 | mkdir | path | mode | |
| 85 | creat | path | mode | |
| 87 | unlink | path | | |
| 89 | readlink | path | buf | bufsiz |
| 90 | chmod | path | mode | |
| 101 | ptrace | request | pid | addr |
| 102 | getuid | | | |
| 105 | setuid | uid | | |
| 131 | sigaltstack | ss | old_ss | |
| 135 | personality | persona | | |
| 157 | prctl | option | arg2 | arg3 |
| 158 | arch_prctl | code | addr | |
| 161 | chroot | path | | |
| 202 | futex | uaddr | op | val |
| 217 | getdents64 | fd | dirp | count |
| 231 | exit_group | status | | |
| 257 | openat | dirfd | pathname | flags (r10=mode) |
| 262 | newfstatat | dirfd | path | statbuf |
| 263 | unlinkat | dirfd | path | flags |
| 269 | faccessat | dirfd | path | mode |
| 275 | splice | fd_in | off_in | fd_out |
| 288 | accept4 | sockfd | addr | addrlen |
| 292 | dup3 | oldfd | newfd | flags |
| 293 | pipe2 | pipefd | flags | |
| 310 | process_vm_readv | pid | local_iov | liovcnt |
| 317 | seccomp | operation | flags | args |
| 318 | getrandom | buf | buflen | flags |
| 319 | memfd_create | name | flags | |
| 322 | execveat | dirfd | path | argv (r10=envp, r8=flags) |
| 332 | statx | dirfd | path | flags |
| 435 | clone3 | cl_args | size | |
| 437 | openat2 | dirfd | path | how |

Pwn shortlist to memorise: **read 0, write 1, open 2, mmap 9, mprotect 10,
rt_sigreturn 15, dup2 33, socket 41, connect 42, execve 59, exit 60,
exit_group 231, openat 257, execveat 322**.

---

## x86 / i386 (`int 0x80`, `/usr/include/asm/unistd_32.h`)

| nr | name | ebx | ecx | edx |
|---:|------|-----|-----|-----|
| 1 | exit | status | | |
| 2 | fork | | | |
| 3 | read | fd | buf | count |
| 4 | write | fd | buf | count |
| 5 | open | pathname | flags | mode |
| 6 | close | fd | | |
| 8 | creat | path | mode | |
| 10 | unlink | path | | |
| 11 | execve | pathname | argv | envp |
| 12 | chdir | path | | |
| 15 | chmod | path | mode | |
| 19 | lseek | fd | offset | whence |
| 20 | getpid | | | |
| 23 | setuid | uid | | |
| 24 | getuid | | | |
| 27 | alarm | seconds | | |
| 29 | pause | | | |
| 33 | access | path | mode | |
| 37 | kill | pid | sig | |
| 39 | mkdir | path | mode | |
| 41 | dup | oldfd | | |
| 42 | pipe | pipefd | | |
| 45 | brk | addr | | |
| 54 | ioctl | fd | req | arg |
| 55 | fcntl | fd | cmd | arg |
| 63 | dup2 | oldfd | newfd | |
| 90 | mmap (old_mmap) | pointer to an arg struct | | |
| 91 | munmap | addr | len | |
| 102 | socketcall | call nr | pointer to args array | |
| 119 | sigreturn | | | |
| 120 | clone | flags | child_stack | parent_tid |
| 122 | uname | buf | | |
| 125 | mprotect | addr | len | prot |
| 172 | prctl | option | arg2 | arg3 |
| 173 | rt_sigreturn | | | |
| 174 | rt_sigaction | sig | act | oact |
| 183 | getcwd | buf | size | |
| 192 | mmap2 | addr | length | prot (esi=flags, edi=fd, ebp=pgoffset) |
| 195 | stat64 | path | statbuf | |
| 197 | fstat64 | fd | statbuf | |
| 220 | getdents64 | fd | dirp | count |
| 221 | fcntl64 | fd | cmd | arg |
| 252 | exit_group | status | | |
| 295 | openat | dirfd | path | flags |
| 330 | dup3 | oldfd | newfd | flags |
| 331 | pipe2 | pipefd | flags | |
| 354 | seccomp | op | flags | args |
| 355 | getrandom | buf | len | flags |
| 356 | memfd_create | name | flags | |
| 358 | execveat | dirfd | path | argv |
| 359 | socket | domain | type | protocol |
| 361 | bind | sockfd | addr | addrlen |
| 362 | connect | sockfd | addr | addrlen |
| 363 | listen | sockfd | backlog | |
| 364 | accept4 | sockfd | addr | addrlen |
| 369 | sendto | sockfd | buf | len |
| 371 | recvfrom | sockfd | buf | len |

Notes:
- `socketcall(102)` is the portable way to do sockets on i386. The direct
  socket syscalls (359+) only exist on Linux 4.3 and newer.
- `mmap2(192)` takes the offset in **pages**, not bytes.
- `sigreturn` is 119 and `rt_sigreturn` is 173 - SROP on i386 normally uses 173.

### socketcall sub-numbers (i386 `ecx` points at the arg array)

```text
1 socket        2 bind          3 connect      4 listen       5 accept
6 getsockname   7 getpeername   8 socketpair   9 send        10 recv
11 sendto      12 recvfrom     13 shutdown    14 setsockopt  15 getsockopt
16 sendmsg     17 recvmsg      18 accept4
```

---

## ARM32 EABI (`arch/arm/tools/syscall.tbl`, number in r7)

| nr | name |
|---:|------|
| 1 | exit |
| 2 | fork |
| 3 | read |
| 4 | write |
| 5 | open |
| 6 | close |
| 11 | execve |
| 19 | lseek |
| 20 | getpid |
| 33 | access |
| 41 | dup |
| 42 | pipe |
| 45 | brk |
| 54 | ioctl |
| 63 | dup2 |
| 91 | munmap |
| 102 | socketcall |
| 119 | sigreturn |
| 120 | clone |
| 125 | mprotect |
| 172 | prctl |
| 173 | rt_sigreturn |
| 192 | mmap2 |
| 248 | exit_group |
| 281 | socket |
| 282 | bind |
| 283 | connect |
| 284 | listen |
| 285 | accept |
| 290 | sendto |
| 292 | recvfrom |
| 322 | openat |
| 358 | dup3 |
| 359 | pipe2 |
| 383 | seccomp |
| 384 | getrandom |
| 385 | memfd_create |
| 387 | execveat |

The low numbers mirror i386, the high ones do not. Always re-check with
`grep __NR_ /usr/arm-linux-gnueabihf/include/asm/unistd*.h` or
`python3 -c "from pwn import *; context.arch='arm'; print(constants.SYS_socket)"`.

---

## AArch64 (`asm-generic/unistd.h`, number in x8)

| nr | name |
|---:|------|
| 17 | getcwd |
| 23 | dup |
| 24 | dup3 |
| 25 | fcntl |
| 29 | ioctl |
| 35 | unlinkat |
| 48 | faccessat |
| 49 | chdir |
| 56 | openat |
| 57 | close |
| 59 | pipe2 |
| 61 | getdents64 |
| 62 | lseek |
| 63 | read |
| 64 | write |
| 66 | writev |
| 73 | ppoll |
| 78 | readlinkat |
| 79 | newfstatat |
| 80 | fstat |
| 93 | exit |
| 94 | exit_group |
| 98 | futex |
| 101 | nanosleep |
| 129 | kill |
| 134 | rt_sigaction |
| 139 | rt_sigreturn |
| 146 | setuid |
| 160 | uname |
| 167 | prctl |
| 172 | getpid |
| 174 | getuid |
| 198 | socket |
| 200 | bind |
| 201 | listen |
| 202 | accept |
| 203 | connect |
| 206 | sendto |
| 207 | recvfrom |
| 214 | brk |
| 215 | munmap |
| 220 | clone |
| 221 | execve |
| 222 | mmap |
| 226 | mprotect |
| 277 | seccomp |
| 278 | getrandom |
| 279 | memfd_create |
| 281 | execveat |
| 291 | statx |
| 435 | clone3 |
| 437 | openat2 |

There is **no `open` and no `dup2`** on this table: use `openat(56, AT_FDCWD, ...)`
and `dup3(24, old, new, 0)`. `AT_FDCWD` is `-100` (`0xffffff9c`).

---

## MIPS o32 (number in `$v0`, base 4000)

| nr | name |
|---:|------|
| 4001 | exit |
| 4002 | fork |
| 4003 | read |
| 4004 | write |
| 4005 | open |
| 4006 | close |
| 4011 | execve |
| 4019 | lseek |
| 4020 | getpid |
| 4033 | access |
| 4041 | dup |
| 4042 | pipe |
| 4045 | brk |
| 4054 | ioctl |
| 4063 | dup2 |
| 4090 | mmap |
| 4091 | munmap |
| 4102 | socketcall |
| 4120 | clone |
| 4125 | mprotect |
| 4192 | mmap2 |
| 4193 | rt_sigreturn |
| 4246 | exit_group |
| 4288 | openat |

MIPS keeps a `socketcall(4102)` interface; direct socket syscalls exist on newer
kernels but their numbers differ between o32/n32/n64, so resolve them on the
target rather than hardcoding:

```bash
grep -E '__NR_(socket|connect|dup3|seccomp|execveat)\b' /usr/mips-linux-gnu/include/asm/unistd.h
```

```python
from pwn import *
context.arch, context.endian = 'mips', 'little'
for name in ('socket', 'connect', 'dup2', 'execve', 'mprotect'):
    print(name, getattr(constants, 'SYS_' + name))
```

n32 numbers start at 6000, n64 at 5000. `execve` is 4011 / 6059 / 5057.

---

## Constants you will need in shellcode

```text
open() flags
  O_RDONLY    0x0        O_WRONLY   0x1        O_RDWR    0x2
  O_CREAT     0x40       O_TRUNC    0x200      O_APPEND  0x400
  O_DIRECTORY 0x10000    O_CLOEXEC  0x80000
  (MIPS differs: O_CREAT 0x100, O_TRUNC 0x200, O_APPEND 0x8)

mmap/mprotect prot
  PROT_NONE 0   PROT_READ 1   PROT_WRITE 2   PROT_EXEC 4     RWX = 7

mmap flags
  MAP_SHARED 0x01   MAP_PRIVATE 0x02   MAP_FIXED 0x10   MAP_ANONYMOUS 0x20

socket
  AF_INET 2   SOCK_STREAM 1   SOCK_DGRAM 2   IPPROTO_TCP 6
  struct sockaddr_in { u16 family; u16 port_BE; u32 addr_BE; u8 pad[8]; }  size 16

openat
  AT_FDCWD = -100 = 0xffffff9c (32-bit) / 0xffffffffffffff9c (64-bit)

seccomp
  PR_SET_NO_NEW_PRIVS 38     SECCOMP_MODE_FILTER 2
  SECCOMP_SET_MODE_FILTER 1  SECCOMP_RET_KILL_PROCESS 0x80000000
  SECCOMP_RET_ALLOW 0x7fff0000   SECCOMP_RET_ERRNO 0x00050000

signals used in pwn
  SIGSEGV 11  SIGALRM 14  SIGTRAP 5  SIGSYS 31 (seccomp kill)  SIGABRT 6
```

## Building a raw syscall in each arch (one line each)

```python
from pwn import *

context.arch = 'amd64'
print(disasm(asm('mov rax, 59; syscall')))

context.arch = 'i386'
print(disasm(asm('mov eax, 11; int 0x80')))

context.arch = 'arm'
print(disasm(asm('mov r7, #11; svc #0')))

context.arch = 'aarch64'
print(disasm(asm('mov x8, #221; svc #0')))

context.arch = 'mips'; context.endian = 'little'
print(disasm(asm('li $v0, 4011; syscall')))
```
