---
title: "z3 Solver (Reversing)"
category: "rev"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "z3", "solver", "reversing", "rev", "scripts"]
summary: "Personal note: z3 Solver (Reversing)."
source:
  name: "Personal notes"
origin_path: "scripts/Reversing/z3 Solver.md"
---

```python
from z3 import *

a=[BitVec("x{}".format(i), 8) for i in range(32)]
s=Solver()
s.add(a[29] == a[5] - a[3] + 70)
s.add(a[22] + a[2] == a[13] + 123)
s.add(a[4] + a[12] == a[5] + 28)
s.add(a[23] * a[25] == a[17] + a[0] + 23)
s.add(a[1] * a[27] == a[22] + a[5] - 21)
s.add(a[13] * a[9] == a[3] * a[28] - 9)
s.add(a[9] == 112)
s.add(a[21] + a[19] == a[6] + 128)
s.add(a[16] == a[15] - a[11] + 48)
s.add(a[27] * a[7] == a[13] * a[1] + 45)
s.add(a[13] == a[13] + a[18] - 101)
s.add(a[20] - a[8] == a[9] + 124)
s.add(a[31] == a[8] - a[31] - 121)
s.add(a[31] * a[20] == a[20] + 4)
s.add(a[24] - a[17] == a[8] + a[21] - 23)
s.add(a[5] + a[7] == a[29] + a[5] + 44)
s.add(a[10] * a[12] == a[1] - a[11] - 36)
s.add(a[0] * a[31] == a[26] - 27)
s.add(a[20] + a[1] == a[10] - 125)
s.add(a[18] == a[14] + a[27] + 2)
s.add(a[11] * a[30] == a[21] + 68)
s.add(a[19] * a[5] == a[1] - 44)
s.add(a[13] - a[26] == a[21] - 127)
s.add(a[23] == a[29] - a[0] + 88)
s.add(a[19] == a[13] * a[8] - 23)
s.add(a[22] + a[6] == a[3] + 83)
s.add(a[12] == a[7] + a[26] - 114)
s.add(a[16] == a[18] - a[5] + 51)
s.add(a[30] - a[8] == a[29] - 77)
s.add(a[20] - a[11] == a[3] - 76)
s.add(a[16] - a[7] == a[17] + 102)
s.add(a[21] + a[1] == a[18] + a[11] + 43)
s.check()
flag=""
model=s.model()
print(model)
for i in a:
    flag+=chr(model[i].as_long())
print(flag)

# HTB{The_sp0000000key_liC3nC3K3Y}
```

---

*From your own notes: `scripts/Reversing/z3 Solver.md`*
