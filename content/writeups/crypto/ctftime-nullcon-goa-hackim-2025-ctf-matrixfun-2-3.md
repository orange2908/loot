---
title: "Matrixfun - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "pcap", "matrixfun", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Then problem can be simplified as below."
source:
  name: "CTFtime writeup #39923"
  url: "https://ctftime.org/writeup/39923"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#Matrixfun"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Matrixfun"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Matrixfun
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39923>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#Matrixfun>

---
Data from pcap:  
![image](<https://hackmd.io/_uploads/rkqAclzKke.png>)

Then problem can be simplified as below.

```python=  
import numpy as np  
from numpy._typing import NDArray  
from gmpy2 import mpz  
from typing import Any

def mpow(a: NDArray[Any], e: int, p: mpz):  
n = a.shape[0]  
c: NDArray[Any] = np.identity(n, dtype=object) // mpz(1)  
for i in range(e.bit_length(), -1, -1):  
c = (c @ c) % p  
if e & (1 << i):  
c = (c @ a) % p  
return c

p = 15021738631187083129  
G = [[8250369131483783446, 7636514724226618982, 13561904710751379340,  
8146037206883500564],  
[4902910229653653467, 12309994425856150343, 6519431793637084561,  
826765390730273580],  
[2293357986500986599, 3690712216774893256, 11221411595572149696,  
6189443780743823928],  
[4526003812557694577, 7070010165244546540, 2773849016628162168,  
2528664545234724542]]  
gorder = 48565318389923

A = [[7124857170442510436, 7098435244666432569, 5016319597248544408,  
3368576660349080409],  
[12766102894582816521, 1075168896515869195, 14940230223165707555,  
13504245377824841154],  
[11005568719346427939, 6351117183900723198, 10504073690105660358,  
765373031704381609],  
[4023860825601216122, 3960044495923291791, 14945314474664374706,  
7318239600236598642]]

B = [[1282048969185546964, 12109372559076385336, 11131078763121815969,  
8203066951109241796],  
[13898425777031025196, 3180683801097577414, 4159815335494956274,  
12490188080505436469],  
[14804946988255087504, 14855384714399608402, 3036218738870877096,  
2244875398266900486],  
[11575966103907984574, 12991978517385440219, 8781891936464379787,  
3191347143541874873]]

iv = bytes.fromhex('b90605c70dc5e0d4d2ab458c93ca3e2c')  
cipher = bytes.fromhex('d772586e1e1ff88b5fbdc2a2f742d6c8fc517acc1d76ce38052db1aa266850cd264232b7d90d283a1d237a6f97d6558f')  
```

We have: 

$$ A = G^a \ \text{or} \ B = G^b$$ 

Where $G$ is a generator matrix and $A$ , $B$ are the public matrices.

To decrypt the cipher text we need to find $a$. Its a discrete logarithm problem in $GL(n,p)$ which is a group of invertible $n\times n$ matrix over $GF(p)$. 

The order is 46 bits , so dlog easily found using baby step gaint step algorithm. 

a = 14694400667272

Now decrypt:

```python=  
Key = mpow(B, a, p)  
```

Decrypt the AES with this shared key to get the flag.
