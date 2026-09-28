---
title: "Chinese Remainder Theorem - CRT (Cryptography)"
category: "crypto"
subcategory: "number-theory"
type: "technique"
tags: ["my-notes", "personal", "chinese-remainder", "chinese", "remainder", "theorem", "crt", "cryptography", "crypto"]
summary: "Personal note: Chinese Remainder Theorem - CRT (Cryptography)."
source:
  name: "Personal notes"
origin_path: "Cryptography/Chinese Remainder Theorem - CRT.md"
---

```python
from Crypto.Util.number import long_to_bytes
from pwn import *
from sympy.ntheory.modular import crt
from gmpy2 import iroot

e = 3
n1 = 
c1 = 
n2 = 
c2 = 
n3 = 

C, _ = crt([n1, n2, n3], [c1, c2])

m, exact = iroot(c1, e)
if exact:
    print(long_to_bytes(m).decode())
```

---

*From your own notes: `Cryptography/Chinese Remainder Theorem - CRT.md`*
