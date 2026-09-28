---
title: "Template (pwn)"
category: "pwn"
type: "technique"
tags: ["my-notes", "personal", "template", "pwn"]
summary: "Personal note: Template (pwn)."
source:
  name: "Personal notes"
origin_path: "pwn/Template.md"
---

```python
from pwn import *
import warnings

warnings.filterwarnings(action='ignore', category=BytesWarning)

elf = ELF("./execute")
context.binary = elf

p = elf.process()
```

---

*From your own notes: `pwn/Template.md`*
