---
title: "Solving Scripts (Reverse)"
category: "rev"
subcategory: "symbolic-execution"
type: "technique"
tags: ["my-notes", "personal", "angr", "eval", "solving", "scripts", "reverse", "rev"]
summary: "just fix the find and avoid offsets…"
source:
  name: "Personal notes"
origin_path: "Reverse/Solving Scripts.md"
---

# Angr

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

just fix the find and avoid offsets…

---

```python
import angr
import sys

def main(argv):
  path_to_binary = "binary"
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  sm = project.factory.simgr(initial_state)
  # list of basic blocks to find or to avoid
  sm.explore(find=[], avoid=[])  
  for state in sm.deadended:
    print(state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

---

*From your own notes: `Reverse/Solving Scripts.md`*
