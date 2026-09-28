---
title: "beginners_rsa - Wani CTF 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "cryptography", "rsa", "factordb", "proof-of-work", "beginners", "wani-ctf", "wani-ctf-2024", "2024", "ctf-writeup"]
summary: "Unlocking the Secrets of RSA Encryption: A Beginner’s Guide with WaniCTF2024"
source:
  name: "CTFtime writeup #39231"
  url: "https://ctftime.org/writeup/39231"
original_source: "https://medium.com/@zeroair41/unlocking-the-secrets-of-rsa-encryption-a-beginners-guide-with-wanictf2024-4f4259ac35d4"
ctf:
  name: "Wani CTF 2024"
  year: 2024
  challenge: "beginners_rsa"
---

## Metadata

- **CTF:** Wani CTF 2024
- **Task:** beginners_rsa
- **Author team:** NCA@Nepal
- **CTFtime tags:** cryptography
- **CTFtime:** <https://ctftime.org/writeup/39231>
- **Original writeup:** <https://medium.com/@zeroair41/unlocking-the-secrets-of-rsa-encryption-a-beginners-guide-with-wanictf2024-4f4259ac35d4>

---
**Unlocking the Secrets of RSA Encryption: A Beginner’s Guide with WaniCTF2024**

###### Find p, q, r, s and a from [factordb.com](http://factordb.com)

```  
#!/usr/bin/env python  
from Crypto.Util.number import inverse, long_to_bytes

n = 317903423385943473062528814030345176720578295695512495346444822768171649361480819163749494400347  
e = 65537  
c = 127075137729897107295787718796341877071536678034322988535029776806418266591167534816788125330265

p = 9953162929836910171  
q = 11771834931016130837  
r = 12109985960354612149  
s = 13079524394617385153   
a = 17129880600534041513

phi = (p-1)*(q-1)*(r-1)*(s-1)*(a-1)

d = inverse(e, phi)

m = pow(c, d, n)  
cipher = long_to_bytes(m)  
print(cipher)  
```
