---
title: "angr Basic Template (Reversing)"
category: "rev"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "angr", "basic", "template", "reversing", "rev", "scripts"]
summary: "Personal note: angr Basic Template (Reversing)."
source:
  name: "Personal notes"
origin_path: "scripts/Reversing/angr Basic Template.md"
---

```python
import angr
import sys

def main(argv):
  path_to_binary = "<binary>"
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

*From your own notes: `scripts/Reversing/angr Basic Template.md`*
