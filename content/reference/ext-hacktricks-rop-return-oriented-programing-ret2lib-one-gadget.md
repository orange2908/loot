---
title: "One Gadget (HackTricks)"
category: "pwn"
subcategory: "ret2lib"
type: "reference"
tags: ["hacktricks", "pwn", "rop", "one-gadget", "angr", "ret2lib", "one", "gadget"]
summary: "onegadget searches a supplied libc for instruction sequences that can invoke execve(\"/bin/sh\", ...) from a single entry address.<sup>[[1]](#references)</sup>"
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/rop-return-oriented-programing/ret2lib/one-gadget.md"
license: "CC BY-NC 4.0"
---

# One Gadget


## Basic Information

[`one_gadget`](https://github.com/david942j/one_gadget) searches a supplied `libc` for instruction sequences that can invoke `execve("/bin/sh", ...)` from a single entry address.<sup>[[1]](#references)</sup>

Each reported gadget has constraints that must hold at the moment control reaches it. For example, a condition such as `[rsp+0x30] == NULL` requires that stack slot to contain a null value; other gadgets may require a writable register or a particular process-environment layout. Padding the payload with null values can satisfy some stack constraints, but always check the exact conditions printed for the selected `libc`.<sup>[[1]](#references)</sup>

![Example constraints reported for a one-gadget](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(754).png)
```python
ONE_GADGET = libc.address + 0x4526a
rop2 = base + p64(ONE_GADGET) + "\x00"*100
```

The offsets reported by `one_gadget` are relative to the matching `libc`; add the runtime `libc` base address before using one in an exploit.

> [!TIP]
> A one-gadget can simplify a ROP chain or an arbitrary-write-to-execution technique, but only when all of the gadget's constraints are satisfied.

### ARM64

The tool supports several architectures, including AArch64, but a particular `libc` may contain no usable gadget. In one recorded test against the AArch64 `libc` shipped with Kali 2023.3, `one_gadget` returned no gadget despite the architecture being supported.<sup>[[1]](#references)</sup>

## Angry Gadget

[`angry_gadget`](https://github.com/ChrisTheCoolHut/angry_gadget) uses [angr](https://github.com/angr/angr) to search for gadgets that reach `execve('/bin/sh', NULL, NULL)` and to reason about their constraints. It can produce additional candidates when `one_gadget` does not find a practical match.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
pip install angry_gadget

angry_gadget.py examples/libc6_2.23-0ubuntu10_amd64.so
```

## References

- [1] [one_gadget - Find `execve("/bin/sh")` gadgets in `libc`](https://github.com/david942j/one_gadget)
- [2] [angry_gadget - Find one-gadgets with angr and satisfiability](https://github.com/ChrisTheCoolHut/angry_gadget)
- [3] [angr binary-analysis framework](https://github.com/angr/angr)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/rop-return-oriented-programing/ret2lib/one-gadget.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
