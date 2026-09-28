---
title: "Basic RSA Template (Crypto)"
category: "crypto"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "rsa", "proof-of-work", "basic", "template", "crypto", "scripts"]
summary: "Personal note: Basic RSA Template (Crypto)."
source:
  name: "Personal notes"
origin_path: "scripts/Crypto/Basic RSA Template.md"
---

```python
from Crypto.Util.number import *

n = 
e = 65537
c = 
p = 
q = 
phi = (p-1) * (q-1)
d = pow(e,-1,phi)
flag = pow(c,d,n)
print(long_to_bytes(flag))
```

---

*From your own notes: `scripts/Crypto/Basic RSA Template.md`*
