---
title: "Single Byte XOR (Crypto)"
category: "crypto"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "xor", "single", "byte", "crypto", "scripts"]
summary: "Personal note: Single Byte XOR (Crypto)."
source:
  name: "Personal notes"
origin_path: "scripts/Crypto/Single Byte XOR.md"
---

```python
from Crypto.Util.number import *

a = 0x54586b6458754f7b215c7c75424f21634f744275517d6d
a = long_to_bytes(a)

for i in range(0x00, 0xff):
    i = long_to_bytes(i) * len(a)
    flag = b''
    for q, w in zip(a, i):
        flag += long_to_bytes(q^w)
    if b'DH' in flag:
        print(flag)
```

---

*From your own notes: `scripts/Crypto/Single Byte XOR.md`*
