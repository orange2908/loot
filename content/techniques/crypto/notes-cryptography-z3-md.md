---
title: "Z3 (Cryptography)"
category: "crypto"
subcategory: "symbolic-execution"
type: "technique"
tags: ["my-notes", "personal", "z3", "cryptography", "crypto"]
summary: "Personal note: Z3 (Cryptography)."
source:
  name: "Personal notes"
origin_path: "Cryptography/z3.md"
---

## find solution
```python
from z3 import *

x = Int('x')
p = Int('p')

s = Solver()

s.add(p*(x**4)-p*(95**4) == -200640142664324295933714)
s.add(x > 0)
s.add(x < 95)

if s.check() == sat:
    print(int(str(s.model()[p]))*4)
```

---

*From your own notes: `Cryptography/z3.md`*
