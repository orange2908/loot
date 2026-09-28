---
title: "glibc Heap - Version-by-Version Differences 2.23 to 2.39"
category: pwn
subcategory: heap
type: reference
tags: [glibc, heap, version, tcache, tcache-key, safe-linking, unsorted-bin-attack, free-hook, malloc-hook, hooks-removed, io-file, fsop, largebin-attack, house-of-force, house-of-orange, house-of-apple, pwndbg, gef]
summary: "What changed in each glibc release, which technique it broke, and what replaced it - the first table to check on any heap challenge."
tools: [pwndbg, gef, pwntools, one-gadget]
related: [glibc-heap-cheatsheet, heap-internals-primer, heap-tcache-poisoning, heap-safe-linking-bypass, house-of-apple]
---

## The one-line rule

`strings ./libc.so.6 | grep -m1 "GNU C Library"` decides your entire exploit plan.
Everything below is a consequence of that one string.

## Master table

| glibc | shipped in | headline change | what it breaks | what you use instead |
|-------|-----------|-----------------|----------------|----------------------|
| 2.23 | Ubuntu 16.04 | baseline: no tcache, fake vtables allowed | - | unlink, fastbin dup, house of force, house of orange, unsorted bin attack |
| 2.24 | - | `IO_validate_vtable` / `_IO_vtable_check` | fake vtables on the heap | point the vtable inside `__libc_IO_vtables` |
| 2.25 | - | `_IO_list_all` hardening continues | - | - |
| 2.26 | Ubuntu 17.10 | **tcache introduced** | nothing; it *enables* tcache dup and poisoning with zero checks | tcache poisoning becomes the default technique |
| 2.27 | Ubuntu 18.04 | tcache widely deployed; `have_fastchunks` added to `malloc_state` | `main_arena` field offsets shift by 8 vs 2.23 | recompute `main_arena+0x60` |
| 2.28 | - | `_IO_str_jumps` `_allocate_buffer` pointer removed | house of apple 1 / old `_IO_str` chains | `_IO_wfile_jumps` |
| 2.29 | Ubuntu 19.04 | **tcache key**, `corrupted top size`, `corrupted unsorted chunks 3`, `corrupted size vs. prev_size` | naive tcache double free, **house of force**, **unsorted bin attack**, naive poison-null-byte | clear the key / house of botcake; largebin attack; keep prev_size consistent |
| 2.30 | - | largebin insert check `bck->fd != victim`, `assert (chunk_main_arena (bck->bk))` | the two-write largebin attack | single-write largebin attack via `bk_nextsize` only |
| 2.31 | Ubuntu 20.04 | `tcache_perthread_struct` grew to 0x290 (counts became `uint16_t`) | offset assumptions in old scripts | recompute the first-chunk offset (`heap+0x2a0`, not `heap+0x260`) |
| 2.32 | - | **Safe-Linking**: `PROTECT_PTR` on tcache and fastbin `fd`; alignment check on the fastbin path | writing a raw target into a tcache `next` | leak the heap, write `(pos>>12) ^ target` |
| 2.33 | - | last release with `__malloc_hook` / `__free_hook` | - | - |
| 2.34 | Ubuntu 22.04 (2.35) era | **hooks removed**; `tcache_key` becomes a random value; `aligned_OK` on the tcache get path; `counts[tc_idx] > 0` check | `__free_hook = system`, `__malloc_hook = one_gadget`, the `hook-0x23` misaligned fake chunk | FSOP / house of apple, `__exit_funcs`, `tls_dtor_list`, GOT |
| 2.35 | Ubuntu 22.04 | `_IO_wfile_jumps` chain is the standard finish | - | house of apple 2 |
| 2.36 | - | `_IO_cleanup` / exit path tweaks | some `_IO_flush_all_lockp` assumptions | verify the call path in gdb |
| 2.37 | - | minor allocator cleanups | - | - |
| 2.38 | Ubuntu 23.10 | - | - | - |
| 2.39 | Ubuntu 24.04 | tcache/largebin checks unchanged; `_IO` layout stable | - | house of apple still works |

## Feature availability matrix

```text
                        2.23 2.26 2.27 2.29 2.31 2.32 2.34 2.35 2.39
tcache                    -    Y    Y    Y    Y    Y    Y    Y    Y
tcache key                -    -    -    Y    Y    Y    Y*   Y*   Y*     (* random)
safe-linking              -    -    -    -    -    Y    Y    Y    Y
tcache alignment check    -    -    -    -    -    -    Y    Y    Y
__free_hook               Y    Y    Y    Y    Y    Y    -    -    -
__malloc_hook             Y    Y    Y    Y    Y    Y    -    -    -
vtable validation         -    Y    Y    Y    Y    Y    Y    Y    Y      (from 2.24)
top size check            -    -    -    Y    Y    Y    Y    Y    Y
unsorted "chunks 3" check -    -    -    Y    Y    Y    Y    Y    Y
largebin bck->fd check    -    -    -    -    Y    Y    Y    Y    Y      (from 2.30)
size vs prev_size check   -    -    -    Y    Y    Y    Y    Y    Y
```

## Technique lifetime

```text
technique                  2.23  2.26  2.27  2.28  2.29  2.31  2.32  2.34  2.35  2.39
unlink (classic)            OK    OK    OK    OK    OK    OK    OK    OK    OK    OK
fastbin dup                 OK    OK    OK    OK    OK    OK    OK    OK    OK    OK
fastbin dup consolidate     OK    OK    OK    OK    ~     ~     ~     ~     ~     ~
tcache dup (plain)          -     OK    OK    OK    X     X     X     X     X     X
tcache dup (key cleared)    -     OK    OK    OK    OK    OK    OK    OK    OK    OK
tcache poisoning            -     OK    OK    OK    OK    OK    OK*   OK*   OK*   OK*
house of botcake            -     OK    OK    OK    OK    OK    OK    OK    OK    OK
unsorted bin leak           OK    OK    OK    OK    OK    OK    OK    OK    OK    OK
unsorted bin attack         OK    OK    OK    OK    X     X     X     X     X     X
largebin attack (2 writes)  OK    OK    OK    OK    OK    X     X     X     X     X
largebin attack (1 write)   OK    OK    OK    OK    OK    OK    OK    OK    OK    OK
house of force              OK    OK    OK    OK    X     X     X     X     X     X
house of spirit             OK    OK    OK    OK    OK    OK    OK    OK    OK    OK
house of einherjar          OK    OK    OK    OK    ~     ~     ~     ~     ~     ~
house of orange (full)      OK    X     X     X     X     X     X     X     X     X
poison null byte (plain)    OK    OK    OK    OK    ~     ~     ~     ~     ~     ~
__free_hook -> system       OK    OK    OK    OK    OK    OK    OK    X     X     X
setcontext+53 (rdi)         OK    OK    OK    OK    X     X     X     X     X     X
setcontext+61 (rdx)         -     -     -     -     OK    OK    OK    OK    OK    OK
FSOP via _IO_list_all       OK    ~     ~     ~     ~     ~     ~     ~     ~     ~
house of apple 2            -     -     -     -     OK    OK    OK    OK    OK    OK
__exit_funcs (PTR_MANGLE)   OK    OK    OK    OK    OK    OK    OK    OK    OK    OK

OK = works as written     X = blocked by a check     ~ = works with extra conditions
*  = requires a heap leak for the safe-linking mangle
```

## The checks, by the release that added them

```text
2.24  IO_validate_vtable()
        "Fatal error: glibc detected an invalid stdio handle"
        vtable must lie inside [__start___libc_IO_vtables, __stop___libc_IO_vtables)

2.29  tcache key
        if (e->key == tcache_key) scan the bin
        "free(): double free detected in tcache 2"

2.29  top size
        if (size > av->system_mem) malloc_printerr("malloc(): corrupted top size")

2.29  unsorted bin unlink
        if (bck->fd != victim) malloc_printerr("malloc(): corrupted unsorted chunks 3")

2.29  consolidation consistency
        if (chunksize(p) != prev_size(next_chunk(p)))
            malloc_printerr("corrupted size vs. prev_size")

2.30  largebin insert
        if (bck->fd != victim) malloc_printerr("malloc(): corrupted unsorted chunks")
        assert (chunk_main_arena (bck->bk))

2.32  safe-linking
        PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr   on tcache next and fastbin fd
        aligned_OK() on the fastbin path

2.34  tcache get hardening
        if (tcache->counts[tc_idx] == 0) return NULL
        if (!aligned_OK(e)) malloc_printerr("malloc(): unaligned tcache chunk detected")
        tcache_key is now a random value from the auxv random pool

2.34  hooks removed
        __malloc_hook, __free_hook, __realloc_hook, __memalign_hook deleted
```

## Structural offsets that move between versions

```text
tcache_perthread_struct chunk size
    2.26 - 2.29   0x250      counts is char[64] at +0x00, entries at +0x40
    2.30 - 2.39   0x290      counts is uint16[64] at +0x10, entries at +0x90
    => the first user chunk is at heap+0x260 (2.26-2.29) or heap+0x2a0 (2.30+)

malloc_state (main_arena)
    2.23          mutex(4) flags(4) fastbinsY at 0x08, top at 0x58, bins at 0x60
                  => the unsorted-bin leak value is main_arena + 0x58
    2.27+         mutex(4) flags(4) have_fastchunks(4+pad) fastbinsY at 0x10,
                  top at 0x60, bins at 0x70
                  => the unsorted-bin leak value is main_arena + 0x60

main_arena offset inside libc (verify per build, never hardcode)
    2.23 Ubuntu 16.04   0x3C4B20     leak value 0x3C4B78
    2.27 Ubuntu 18.04   0x3EBC40     leak value 0x3EBCA0
    2.31 Ubuntu 20.04   0x1ECB80     leak value 0x1ECBE0
    2.35 Ubuntu 22.04   0x219C80     leak value 0x219CE0

main_arena when not exported
    2.23 - 2.33   main_arena == __malloc_hook + 0x10
    2.34+         no hooks; use a debug libc, libc.rip, or the build's own symbols
```

## Decision flow

```text
read the version string
  |
  +-- 2.23 .............. no tcache. unlink / fastbin dup / house of force /
  |                       house of orange / unsorted bin attack all available.
  |                       Fake vtables on the heap are fine.
  |
  +-- 2.26 - 2.28 ....... tcache with NO checks. tcache dup and poisoning are
  |                       two-line exploits. __free_hook = system to finish.
  |
  +-- 2.29 - 2.31 ....... tcache key. Clear it, fill the bin, or house of botcake.
  |                       House of force and unsorted bin attack are dead;
  |                       use the largebin attack for a big-value write.
  |                       Hooks still present: __free_hook = system, or
  |                       __free_hook = setcontext+61 for a seccomp'd challenge.
  |
  +-- 2.32 - 2.33 ....... add safe-linking. Leak the heap FIRST (free one chunk,
  |                       show it: the value is (heap >> 12)), then mangle every
  |                       pointer you write. Hooks still present.
  |
  +-- 2.34+ ............. no hooks. Get a libc leak, then:
                            no seccomp  -> house of apple 2 (_IO_wfile_jumps)
                            seccomp     -> house of apple 2 into setcontext+61
                            heap ptr write only -> largebin attack on _IO_list_all
                            can leak fs:0x30    -> __exit_funcs with PTR_MANGLE
                            Partial RELRO       -> GOT
```

## Version fingerprinting from behaviour alone

Useful when the challenge does not ship a libc.

```text
1. malloc(0x18) -> A ; free(A) ; show(A)
     prints a small value like 0x55e4c1        -> safe-linking     -> 2.32+
     prints a full heap pointer                -> no safe-linking  -> <= 2.31
     prints nothing (fd == 0, unreadable)      -> inconclusive

2. free(A) twice
     "free(): double free detected in tcache 2" -> tcache key      -> 2.29+
     no message, works                          -> no key          -> 2.26 - 2.28
     "double free or corruption (fasttop)"      -> no tcache       -> 2.23

3. first chunk address & 0xfff
     0x2a0  -> tcache struct is 0x290          -> 2.30+
     0x260  -> tcache struct is 0x250          -> 2.26 - 2.29
     0x010  -> no tcache struct                -> 2.23

4. poison a tcache entry to an unaligned address
     "malloc(): unaligned tcache chunk detected" -> 2.34+

5. overwrite top->size with -1 then malloc big
     "malloc(): corrupted top size"            -> 2.29+
```

## Ubuntu / Debian to glibc mapping

```text
Ubuntu 16.04 xenial    2.23
Ubuntu 17.10 artful    2.26
Ubuntu 18.04 bionic    2.27
Ubuntu 19.04 disco     2.29
Ubuntu 19.10 eoan      2.30
Ubuntu 20.04 focal     2.31
Ubuntu 21.04 hirsute   2.33
Ubuntu 21.10 impish    2.34
Ubuntu 22.04 jammy     2.35
Ubuntu 23.04 lunar     2.37
Ubuntu 23.10 mantic    2.38
Ubuntu 24.04 noble     2.39
Debian 10 buster       2.28
Debian 11 bullseye     2.31
Debian 12 bookworm     2.36
```

Point releases within one version differ in symbol offsets. Always derive addresses
from the libc the challenge gave you; the numbers above are for orientation only.
