---
title: "Assembly Reference - x86/x64, AArch64, ARM32, MIPS and Compiler Idioms"
category: rev
subcategory: assembly
type: reference
tags: [assembly, x86, x86-64, aarch64, arm, arm32, thumb, mips, registers, calling-convention, syscall, compiler-idiom, magic-multiply, jump-table, stack-canary, plt, got, endianness, flags]
summary: "Registers, calling conventions and instruction equivalents across x86-64, AArch64, ARM32 and MIPS, plus a table of what each compiler idiom actually means."
tools: [objdump, gdb, radare2, ghidra, capstone]
related: [gdb-reversing-cheatsheet, radare2-cheatsheet, file-format-cheatsheet, crackme-patterns, shellcode-analysis, firmware-raw-blob-loading]
---

## x86-64 registers

| 64 | 32 | 16 | 8 low | Conventional use (SysV) |
|---|---|---|---|---|
| `rax` | `eax` | `ax` | `al` | return value; syscall number |
| `rbx` | `ebx` | `bx` | `bl` | callee-saved |
| `rcx` | `ecx` | `cx` | `cl` | arg 4; loop counter; clobbered by syscall |
| `rdx` | `edx` | `dx` | `dl` | arg 3; high half of mul/div |
| `rsi` | `esi` | `si` | `sil` | arg 2; string source |
| `rdi` | `edi` | `di` | `dil` | arg 1; string destination |
| `rbp` | `ebp` | `bp` | `bpl` | frame pointer (callee-saved) |
| `rsp` | `esp` | `sp` | `spl` | stack pointer |
| `r8`-`r15` | `r8d`-`r15d` | `r8w`- | `r8b`- | args 5-6 (`r8`,`r9`); `r10` syscall arg4; `r12`-`r15` callee-saved |
| `rip` | | | | instruction pointer (RIP-relative addressing) |
| `xmm0`-`xmm15` | | | | floats/SSE; `xmm0` returns floats |

**Writing to a 32-bit register zero-extends into the full 64-bit register**
(`mov eax, 1` clears the top 32 bits of `rax`); writing to a 16- or 8-bit register does not.
This is why compilers emit `xor eax, eax` rather than `xor rax, rax` (one byte shorter, same
effect).

### FLAGS

| Bit | Name | Set when |
|---|---|---|
| CF | carry | unsigned overflow / borrow |
| ZF | zero | result == 0 |
| SF | sign | result's high bit set (negative) |
| OF | overflow | signed overflow |
| PF | parity | even number of set bits in the low byte |
| DF | direction | `std`/`cld` - direction of string ops |

| Jump | Taken when | Signed? |
|---|---|---|
| `je`/`jz` | ZF=1 | - |
| `jne`/`jnz` | ZF=0 | - |
| `jg`/`jnle` | ZF=0 and SF=OF | signed `>` |
| `jge`/`jnl` | SF=OF | signed `>=` |
| `jl`/`jnge` | SF!=OF | signed `<` |
| `jle`/`jng` | ZF=1 or SF!=OF | signed `<=` |
| `ja`/`jnbe` | CF=0 and ZF=0 | unsigned `>` |
| `jae`/`jnb`/`jnc` | CF=0 | unsigned `>=` |
| `jb`/`jnae`/`jc` | CF=1 | unsigned `<` |
| `jbe`/`jna` | CF=1 or ZF=1 | unsigned `<=` |
| `js` / `jns` | SF=1 / SF=0 | sign test |
| `jo` / `jno` | OF=1 / OF=0 | overflow |

Seeing `ja`/`jb` instead of `jg`/`jl` tells you the C types were **unsigned**. That matters
when you model the check in z3 (`ULT` vs `<`).

## Calling conventions

| ABI | Integer args | Return | Callee-saved | Notes |
|---|---|---|---|---|
| SysV x86-64 (Linux/macOS) | rdi, rsi, rdx, rcx, r8, r9 | rax (rdx:rax for 128-bit) | rbx, rbp, r12-r15 | 16-byte stack alignment at `call`; 128-byte red zone below rsp |
| Microsoft x64 | rcx, rdx, r8, r9 | rax | rbx, rbp, rdi, rsi, r12-r15 | caller reserves 32 bytes of "shadow space" |
| Linux x86-64 syscall | rdi, rsi, rdx, r10, r8, r9 | rax | - | number in rax; `syscall` clobbers rcx and r11 |
| x86 cdecl | stack, right to left | eax | ebx, esi, edi, ebp | caller cleans the stack |
| x86 stdcall | stack, right to left | eax | same | callee cleans (`ret N`) |
| x86 fastcall | ecx, edx, then stack | eax | same | |
| x86 thiscall (MSVC) | ecx = this, rest on stack | eax | same | |
| x86 int 0x80 | ebx, ecx, edx, esi, edi, ebp | eax | - | 32-bit Linux syscalls |
| AArch64 AAPCS64 | x0-x7 | x0 (x0,x1 for 128-bit) | x19-x28, sp, fp(x29) | x30 = lr; `svc #0` with the number in x8 |
| ARM32 AAPCS | r0-r3 | r0 (r0,r1) | r4-r11 | lr = r14, sp = r13, pc = r15; `svc #0`, number in r7 |
| MIPS O32 | a0-a3 ($4-$7) | v0, v1 ($2,$3) | s0-s7 | `syscall`, number in v0; branch delay slots! |
| Go (1.17+) | rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11 | same registers | - | r14 = goroutine pointer |

## Instruction equivalence table

| Operation | x86-64 | AArch64 | ARM32 | MIPS |
|---|---|---|---|---|
| move reg | `mov rax, rbx` | `mov x0, x1` | `mov r0, r1` | `move $v0, $a0` |
| load immediate | `mov eax, 1` | `mov w0, #1` | `mov r0, #1` | `li $v0, 1` |
| load from memory | `mov rax, [rbx]` | `ldr x0, [x1]` | `ldr r0, [r1]` | `lw $v0, 0($a0)` |
| load byte (zero-ext) | `movzx eax, byte [rbx]` | `ldrb w0, [x1]` | `ldrb r0, [r1]` | `lbu $v0, 0($a0)` |
| load byte (sign-ext) | `movsx eax, byte [rbx]` | `ldrsb w0, [x1]` | `ldrsb r0, [r1]` | `lb $v0, 0($a0)` |
| store | `mov [rbx], rax` | `str x0, [x1]` | `str r0, [r1]` | `sw $v0, 0($a0)` |
| add | `add rax, rbx` | `add x0, x0, x1` | `add r0, r0, r1` | `addu $v0, $v0, $a0` |
| subtract | `sub rax, rbx` | `sub x0, x0, x1` | `sub r0, r0, r1` | `subu` |
| multiply | `imul rax, rbx` | `mul x0, x0, x1` | `mul r0, r0, r1` | `mult` + `mflo` |
| xor | `xor eax, ebx` | `eor w0, w0, w1` | `eor r0, r0, r1` | `xor $v0,$v0,$a0` |
| and / or | `and` / `or` | `and` / `orr` | `and` / `orr` | `and` / `or` |
| not | `not rax` | `mvn x0, x0` | `mvn r0, r0` | `nor $v0,$v0,$zero` |
| shift left | `shl eax, 3` | `lsl w0, w0, #3` | `lsl r0, r0, #3` | `sll $v0,$v0,3` |
| logical shift right | `shr eax, 3` | `lsr w0, w0, #3` | `lsr r0, r0, #3` | `srl` |
| arithmetic shift right | `sar eax, 3` | `asr w0, w0, #3` | `asr r0, r0, #3` | `sra` |
| rotate | `ror eax, 3` | `ror w0, w0, #3` | `ror r0, r0, #3` | (synthesised) |
| compare | `cmp rax, rbx` | `cmp x0, x1` | `cmp r0, r1` | `slt`/`beq` pairs |
| test for zero | `test eax, eax` | `cbz w0, label` | `cmp r0, #0` | `beqz $v0, label` |
| conditional branch | `je label` | `b.eq label` | `beq label` | `beq $a,$b,label` |
| unconditional jump | `jmp label` | `b label` | `b label` | `j label` |
| call | `call func` | `bl func` | `bl func` | `jal func` |
| return | `ret` | `ret` (uses x30) | `bx lr` / `pop {pc}` | `jr $ra` |
| push / pop | `push rax` / `pop rax` | `stp x0,x1,[sp,#-16]!` / `ldp` | `push {r0}` / `pop {r0}` | manual `sw`/`addiu sp` |
| syscall | `syscall` | `svc #0` | `svc #0` | `syscall` |
| no-op | `nop` (`0x90`) | `nop` (`1f 20 03 d5`) | `nop` (`00 f0 20 e3`) | `nop` (`sll $0,$0,0` = 4 zero bytes) |

### Architecture quirks that bite

- **MIPS has branch delay slots**: the instruction *after* a branch executes regardless of
  whether the branch is taken. In a disassembly, that instruction logically belongs *before*
  the branch.
- **ARM32 `pc` reads as the current instruction + 8** (ARM mode) or + 4 (Thumb). PC-relative
  constant pools are everywhere: `ldr r0, [pc, #0x20]` loads a literal stored after the
  function.
- **Thumb addresses are odd**: a function pointer to Thumb code has bit 0 set. `0x08000245`
  means "Thumb code at `0x08000244`".
- **AArch64 has no `push`/`pop`**: `stp x29, x30, [sp, #-0x10]!` is the prologue,
  `ldp x29, x30, [sp], #0x10` the epilogue.
- **x86 string instructions** (`rep movsb`, `rep stosq`, `scasb`) are inlined
  memcpy/memset/strlen - see the idiom table.
- **Endianness**: x86 and ARM (usually) little-endian; MIPS, PowerPC, SPARC and most network
  formats big-endian. `0x41424344` little-endian in memory is `44 43 42 41`.

## Common Linux syscall numbers

| Syscall | x86-64 (`rax`) | x86 (`eax`) | AArch64 (`x8`) | ARM32 (`r7`) |
|---|---|---|---|---|
| read | 0 | 3 | 63 | 3 |
| write | 1 | 4 | 64 | 4 |
| open | 2 | 5 | (openat 56) | 5 |
| close | 3 | 6 | 57 | 6 |
| mmap | 9 | 90 | 222 | 192 |
| mprotect | 10 | 125 | 226 | 125 |
| ptrace | 101 | 26 | 117 | 26 |
| execve | 59 | 11 | 221 | 11 |
| exit | 60 | 1 | 93 | 1 |

## Compiler idioms - what this weird code actually means

### `test eax, eax` / `test rax, rax`

```asm
test eax, eax
je   .Lzero
```
`test` is a non-destructive `and`, so `test eax,eax` sets ZF exactly when `eax == 0`.
It is one byte shorter than `cmp eax, 0`. Read it as `if (x == 0)`.

### `xor eax, eax`

Zeroing a register. Two bytes, breaks the dependency chain. Read it as `x = 0`.

### `lea` doing arithmetic

```asm
lea eax, [rdi + rdi*2]      ; eax = rdi * 3
lea eax, [rdi*4 + 5]        ; eax = rdi*4 + 5
lea rax, [rip + 0x2e75]     ; rax = address of a global/string (RIP-relative)
```
`lea` computes an address but does not dereference, so compilers use it as a free
three-operand `add`/`mul`. Only `*1 *2 *4 *8` scales exist, so `*3`, `*5`, `*9` appear as
`base + index*2/4/8`.

### Division by a constant (magic multiply)

```asm
; unsigned x / 10
mov  eax, edi
mov  edx, 0xCCCCCCCD         ; the magic number
mul  edx                     ; edx:eax = eax * magic
shr  edx, 3                  ; result in edx
```
The compiler replaces division by a constant with a multiply-high plus a shift.
Recover the divisor: `d ~= 2^(32+shift) / magic`. For `0xCCCCCCCD` and `shr 3`:
`2^35 / 0xCCCCCCCD = 10`. Signed versions use `imul` plus an extra `sar` and a correction
for negatives (`shr edx,31; add`). **The magic constant is not part of the algorithm** -
do not model it in z3; model the division.

```python
# Recover the divisor from a magic multiply
def divisor(magic: int, shift: int, bits: int = 32) -> int:
    return round((1 << (bits + shift)) / magic)

if __name__ == "__main__":
    assert divisor(0xCCCCCCCD, 3) == 10
    assert divisor(0xAAAAAAAB, 1) == 3
    assert divisor(0x92492493, 2) == 7      # note the +1 correction form for 7
    print("[+] magic-divisor recovery OK")
```

### Modulo by a power of two

```asm
and eax, 7          ; x % 8 for UNSIGNED x
; signed x % 8 is uglier:
mov edx, eax
sar edx, 31
shr edx, 29
add eax, edx
and eax, 7
sub eax, edx
```

### Jump table (a `switch`)

```asm
cmp  edi, 7
ja   .Ldefault                 ; unsigned compare catches negatives too
mov  eax, edi
lea  rdx, [rip + 0x1a34]       ; the table
movsxd rax, dword [rdx + rax*4]
add  rax, rdx                  ; entries are 32-bit offsets FROM the table base
jmp  rax
```
The table lives in `.rodata` (or `.text` on some compilers). Entries may be absolute
addresses (older/32-bit) or offsets relative to the table. Ghidra and IDA decode these
automatically; radare2 needs `aae`.

### Stack canary

```asm
; prologue
mov  rax, qword fs:[0x28]      ; the canary from the TLS block
mov  qword [rbp-8], rax
xor  eax, eax
; ...
; epilogue
mov  rax, qword [rbp-8]
sub  rax, qword fs:[0x28]      ; (or xor)
jne  .Lfail
...
.Lfail:
call __stack_chk_fail
```
`fs:[0x28]` (x86-64) / `gs:[0x14]` (x86) is the canary. Seeing this means the function has a
local buffer. It is noise for RE - ignore it.

### PIE, PLT and GOT

```asm
call 0x401030 <puts@plt>
; the PLT stub:
0x401030:  jmp  qword [rip + 0x2fe2]      ; -> GOT entry
0x401036:  push 0                         ; index into the relocation table
0x40103b:  jmp  0x401020                  ; -> the resolver (_dl_runtime_resolve)
```
Before the first call the GOT entry points back at `push`/`jmp`, so the loader resolves the
symbol lazily. After the first call it points at the real function. With
`-Wl,-z,now`/full RELRO the GOT is resolved at load time and made read-only.

`lea rax, [rip + 0x2e75]` plus a `call` is how PIE code takes the address of a global.
Ghidra shows the resolved target; raw `objdump` shows the offset.

### Inlined memcpy / memset / strlen

```asm
rep movsb            ; memcpy(rdi, rsi, rcx)
rep stosq            ; memset-like fill of rcx qwords from rax
repne scasb          ; strlen-ish scan for al in [rdi]
movdqu xmm0, [rsi]   ; SSE copy - a 16-byte-at-a-time memcpy
pcmpeqb xmm0, xmm1   ; SSE compare - an inlined memcmp/strlen
pmovmskb eax, xmm0   ; extract the comparison bitmask
```
SSE string loops (`pcmpeqb` + `pmovmskb` + `bsf`) are libc's `strlen`/`strcmp`, not the
challenge's logic.

### Loop induction and unrolling

```asm
; a for(i=0;i<4;i++) loop the compiler unrolled
movzx eax, byte [rdi]
xor   eax, 0x5a
mov   [rsi], al
movzx eax, byte [rdi+1]
xor   eax, 0x5b
mov   [rsi+1], al
...
```
Four nearly identical blocks with incrementing offsets and a changing constant is one loop.
Reconstruct the pattern (`key = 0x5a + i`) rather than transcribing each block.

### `setcc` and branchless code

```asm
cmp  eax, ebx
sete al              ; al = (eax == ebx)
movzx eax, al
; or:
cmovne eax, edx      ; eax = (cond) ? eax : edx
```
Branchless comparison. `sete/setne/setg/setl/...` mirror the jump conditions.

### Tail call

```asm
add rsp, 0x18
jmp some_function      ; NOT call - the callee returns directly to our caller
```
A `jmp` to another function at the end of a function is `return some_function(...)`.
Very common in Go and Rust output.

### Function prologue/epilogue by architecture

```asm
; x86-64 with a frame pointer
push rbp
mov  rbp, rsp
sub  rsp, 0x20
...
leave                ; mov rsp, rbp ; pop rbp
ret
; x86-64 without (-O2 default)
sub  rsp, 0x18
...
add  rsp, 0x18
ret

; AArch64
stp  x29, x30, [sp, #-0x20]!
mov  x29, sp
...
ldp  x29, x30, [sp], #0x20
ret

; ARM32
push {r4, r5, r7, lr}
add  r7, sp, #8
...
pop  {r4, r5, r7, pc}

; MIPS O32
addiu $sp, $sp, -32
sw    $ra, 28($sp)
sw    $fp, 24($sp)
...
lw    $ra, 28($sp)
addiu $sp, $sp, 32
jr    $ra
nop                  ; delay slot
```

## Quick byte-level reference (x86)

| Bytes | Instruction |
|---|---|
| `90` | nop |
| `cc` | int3 (breakpoint) |
| `c3` | ret |
| `c9` | leave |
| `55` | push rbp |
| `5d` | pop rbp |
| `31 c0` | xor eax, eax |
| `48 31 c0` | xor rax, rax |
| `b8 xx xx xx xx` | mov eax, imm32 |
| `e8 rel32` | call |
| `e9 rel32` | jmp near |
| `eb rel8` | jmp short |
| `74 rel8` / `75 rel8` | je / jne |
| `0f 84 rel32` / `0f 85 rel32` | je / jne near |
| `0f 05` | syscall |
| `cd 80` | int 0x80 |
| `0f 31` | rdtsc |
| `0f a2` | cpuid |
| `f3 0f 1e fa` | endbr64 (CET marker, starts most functions on modern builds) |
| `66 0f 1f 44 00 00` | 6-byte nop (alignment padding) |

## Assembling and disassembling one-liners

```sh
# Disassemble raw bytes
rasm2 -a x86 -b 64 -d '4831c0c3'
echo -ne '\x48\x31\xc0\xc3' | ndisasm -b 64 -
python3 -c "from capstone import *; [print(i.mnemonic, i.op_str) for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(bytes.fromhex('4831c0c3'), 0)]"
# Assemble
rasm2 -a x86 -b 64 'xor rax, rax; ret'
python3 -c "from keystone import *; print(Ks(KS_ARCH_X86, KS_MODE_64).asm('xor rax,rax; ret')[0])"
# Other architectures
rasm2 -a arm -b 64 'mov x0, #1'
rasm2 -a mips -b 32 -e 'addiu $sp, $sp, -32'      # -e = big endian
# GNU as + objdump round trip
echo 'mov $1, %eax' | as -o /tmp/a.o - && objdump -d /tmp/a.o
```

## References

- Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (instruction set)
  and Volume 1 (registers, FLAGS).
- ARM Architecture Reference Manual (ARMv8-A) and the AAPCS64 procedure call standard.
- System V Application Binary Interface, AMD64 Architecture Processor Supplement
  (argument registers, red zone, stack alignment).
- Agner Fog's instruction tables, and "Hacker's Delight" for the magic-multiply derivation.
