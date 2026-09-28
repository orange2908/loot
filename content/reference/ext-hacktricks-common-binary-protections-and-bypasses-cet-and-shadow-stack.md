---
title: "CET & Shadow Stack (HackTricks)"
category: "pwn"
subcategory: "common-binary-protections-and-bypasses"
type: "reference"
tags: ["hacktricks", "pwn", "rop", "cet", "shadow", "stack", "common-binary-protections-and-by", "common", "binary", "protections", "bypasses", "cet-and-shadow-stack"]
summary: "Intel Control-flow Enforcement Technology (CET) is a set of processor features intended to make control-flow hijacking techniques such as return-oriented programming (ROP) and jump-oriented programmin"
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/common-binary-protections-and-bypasses/cet-and-shadow-stack.md"
license: "CC BY-NC 4.0"
---

# CET & Shadow Stack


## Control Flow Enforcement Technology (CET)

Intel **Control-flow Enforcement Technology (CET)** is a set of processor features intended to make control-flow hijacking techniques such as return-oriented programming (ROP) and jump-oriented programming (JOP) harder. CET must also be supported and enabled by the operating system, loader, and application; CPU support alone does not protect a process.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

CET provides two complementary mechanisms:<sup>[[1]](#references)</sup>

- **Indirect Branch Tracking (IBT)** requires an indirect `CALL` or `JMP` to land on an `ENDBR` instruction inserted at intended targets. This reduces the set of usable indirect-branch targets and constrains JOP/COP attacks.
- **Shadow Stack (SHSTK)** maintains a protected second copy of return addresses. On a return, the processor compares the normal-stack address with the shadow-stack address and raises a control-protection fault if they differ.

## Shadow Stack

The shadow stack is a separate memory region used for control-transfer state. Ordinary application stores cannot modify it; the processor writes a return address to both stacks when executing a call and checks both copies on return. Specialized instructions and operating-system support handle legitimate updates such as signal delivery or context restoration.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## How CET and Shadow Stack Prevent Attacks

ROP chains commonly corrupt saved return addresses, while JOP/COP chains redirect indirect jumps or calls. CET addresses these paths separately:

- **IBT** blocks indirect transfers to locations that do not begin with the required landing-pad instruction. It reduces the available gadget space but does not prove that every permitted target is safe.
- **Shadow stack** detects a corrupted return address before the processor uses it. The resulting fault lets the operating system terminate or otherwise handle the offending process.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

CET is therefore a mitigation, not a substitute for memory safety. Its practical coverage depends on which CET features the CPU and operating system support and whether the binary and runtime enable them.<sup>[[2]](#references)</sup>

## References

- [1] [Intel - A technical look at Control-flow Enforcement Technology](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)
- [2] [Linux kernel documentation - Control-flow Enforcement Technology shadow stack](https://docs.kernel.org/next/x86/shstk.html)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/common-binary-protections-and-bypasses/cet-and-shadow-stack.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
