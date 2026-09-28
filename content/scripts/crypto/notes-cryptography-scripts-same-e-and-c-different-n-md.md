---
title: "Same E And C, Different N"
category: "crypto"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "gcd", "proof-of-work", "same", "different", "crypto", "cryptography"]
summary: "Personal note: Same E And C, Different N."
source:
  name: "Personal notes"
origin_path: "Cryptography/scripts/same e and c, different n.md"
---

```python
from Crypto.Util.number import long_to_bytes, GCD, inverse

e = 65537
n1 = 10774956107756558832108256138345844179293119585008372146975768319635082740438296744467087687647098182598335288752125695150526963609953052126350295547317539
n2 = 9409964411736576904993884791981422408072900042543624036083887840817239046190712989509839092437985165399385449632248446665918290535506817646935373573512343
c = 3960375926057920103803119759164486505823835410608533610321042690168249877842203615513163015685014885664792641991940798623459499630350258444105253714260142

cf = GCD(n1, n2)
print(f"{cf = }")

if cf != 1:
    p = cf
    q1 = n1 // p
    q2 = n2 // p
    # print(f"p: {p}")
    # print(f"q1: {q1}")
    # print(f"q2: {q2}")

    phi1 = (p - 1) * (q1 - 1)
    phi2 = (p - 1) * (q2 - 1)
    # print(f"phi1: {phi1}")
    # print(f"phi2: {phi2}")

    d1 = inverse(e, phi1)
    d2 = inverse(e, phi2)
    # print(f"d1: {d1}")
    # print(f"d2: {d2}")

    m1 = pow(c, d1, n1)
    m2 = pow(c, d2, n2)
    print(f"m1: {m1}")
    # print(f"m2: {m2}")

    flag = long_to_bytes(m1)
    print(flag)
else:
    print("lulz")
```

---

*From your own notes: `Cryptography/scripts/same e and c, different n.md`*
