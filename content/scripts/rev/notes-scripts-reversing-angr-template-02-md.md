---
title: "angr Template - 02 (Reversing)"
category: "rev"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "angr", "eval", "template", "reversing", "rev", "scripts"]
summary: "Personal note: angr Template - 02 (Reversing)."
source:
  name: "Personal notes"
origin_path: "scripts/Reversing/angr Template - 02.md"
---

```python
#!/usr/bin/python

import angr
import claripy
import logging


BASE_ADDR = 0x400000


def rebase(addr):
    return BASE_ADDR + addr


def main():
    p = angr.Project('rebuilding')

    argv1 = claripy.BVS("argv1", 8*0x21)
    initial_state = p.factory.entry_state(args=["./rebuilding", argv1])

    sm = p.factory.simulation_manager(initial_state)
    sm.explore(find=rebase(0x000009f2), avoid=rebase(0x00000a05))

    if not len(sm.found):
        print("no solution")
        return 1


    found = sm.found[0]
    solution = found.solver.eval(argv1, cast_to=bytes)
    solution = solution[:solution.find(b'\x00')]
    return solution


if __name__ == "__main__":
    print([main()])
```

---

*From your own notes: `scripts/Reversing/angr Template - 02.md`*
