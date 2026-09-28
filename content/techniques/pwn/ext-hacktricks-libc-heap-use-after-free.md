---
title: "Use-After-Free (HackTricks)"
category: "pwn"
subcategory: "use-after-free"
type: "technique"
tags: ["hacktricks", "pwn", "heap", "tcache", "use-after-free", "heap-feng-shui", "use", "after", "free"]
summary: "A use-after-free (UAF) occurs when a program continues to use a pointer or reference after the referenced allocation has been freed."
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/libc-heap/use-after-free/README.md"
license: "CC BY-NC 4.0"
difficulty: "hard"
when_to_use: ["Basic Information", "First-Fit Attack"]
---

# Use-After-Free


## Basic Information

A use-after-free (UAF) occurs when a program continues to use a pointer or reference after the referenced allocation has been freed. The stale reference is often called a _dangling pointer_. If the allocator later reuses that region, the stale pointer may refer to data owned by a different object.<sup>[[1]](#references)</sup>

Accessing freed memory is invalid, but it does not necessarily fail immediately. Depending on the operation and the allocator state, a UAF may cause a crash, disclose memory, corrupt a live object, or enable code execution. Exploitation commonly involves reclaiming the freed region with attacker-influenced data before the program dereferences the stale pointer; overwriting a function pointer or another control-sensitive field can then redirect execution.<sup>[[1]](#references)</sup>

## First-Fit Attack

A first-fit attack uses predictable allocation selection to reclaim a freed chunk with a chosen allocation. In a UAF scenario, heap grooming can place attacker-controlled contents where the dangling pointer will later read or write. In glibc, some same-size free lists—notably tcache bins and fastbins—are last-in, first-out, so a matching allocation may return the most recently freed chunk. Other bins and allocators use different selection rules, so the exact result depends on the glibc version, size class, cache/bin state, and allocation sequence.<sup>[[2]](#references)</sup> See the dedicated page for details:

first-fit.md

## References

- [1] [MITRE CWE-416 - Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [2] [glibc source - `malloc/malloc.c`](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/libc-heap/use-after-free/README.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
