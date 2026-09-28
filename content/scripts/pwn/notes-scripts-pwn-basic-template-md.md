---
title: "Basic Template (pwn)"
category: "pwn"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "basic", "template", "pwn", "scripts"]
summary: "Personal note: Basic Template (pwn)."
source:
  name: "Personal notes"
origin_path: "scripts/pwn/Basic Template.md"
---

```python
from pwn import *

BIN_NAME = ''
REMOTE_ADDR = ''
REMOTE_PORT = 
LOCAL = False

vuln = ELF(BIN_NAME)
context.binary = vuln

if LOCAL: stream = process(BIN_NAME)
else: stream = remote(REMOTE_ADDR, REMOTE_PORT)

offset = 

stream.sendline(b'A'* offset + p64())

stream.interactive()
```

---

*From your own notes: `scripts/pwn/Basic Template.md`*
