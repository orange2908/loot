---
title: "Matrixfun - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "sage", "pohlig-hellman", "deserialization", "base64", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The task is based on Diffie-Hellman protocol variation that uses the special linear group (matrices with det=1)."
source:
  name: "CTFtime writeup #40036"
  url: "https://ctftime.org/writeup/40036"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Matrixfun"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Matrixfun
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40036>

---
Solved by maximxls:  
The task is based on Diffie-Hellman protocol variation that uses the special linear group (matrices with det=1). This makes it possible to calculate the discrete logarithm using the Pohlig-Hellman algorithm. I used the generic implementation included with sagemath (I have modified the code inside a bit for it to work with matrices properly). The algorithm takes some time, but in the end it finishes and gives a private key that can be used to generate the shared secret. After that we just decode the AES ciphertext and get the flag.  
```  
from sage.all import *  
from pickle import loads  
from base64 import b64decode  
import numpy as np  
import hashlib

p, g, gorder = loads(b64decode("gASVwwEAAAAAAACKCXkvq0yy73fQAIwWbnVtcHkuX2NvcmUubXVsdGlhcnJheZSMDF9yZWNvbnN0cnVjdJSTlIwFbnVtcHmUjAduZGFycmF5lJOUSwCFlEMBYpSHlFKUKEsBSwRLBIaUaAOMBWR0eXBllJOUjAJPOJSJiIeUUpQoSwOMAXyUTk5OSv////9K/////0s/dJRiiV2UKIwSc3ltcHkuY29yZS5udW1iZXJzlIwHSW50ZWdlcpSTlIoIFmHwQwMzf3KFlIGUaBWKCGZWkYOuWfpphZSBlGgVigmMXwj6epA1vACFlIGUaBWKCBQCaBuuiQxxhZSBlGgVigjbhyKM4KIKRIWUgZRoFYoJR8sxjLXi1aoAhZSBlGgVigiRTSDFrKx5WoWUgZRoFYoILKMQE75CeQuFlIGUaBWKCOdGMiDwpNMfhZSBlGgVigjI3g/5NAs4M4WUgZRoFYoJwP2GgGR2upsAhZSBlGgVigg4gnxUU1LlVYWUgZRoFYoIcaaQ23yYzz6FlIGUaBWKCOxNzWnJuB1ihZSBlGgVigh4LrDw+7B+JoWUgZRoFYoIvibXpgGfFyOFlIGUZXSUYooGoxCNfissh5Qu"))

A = loads(b64decode("gASVsQEAAAAAAACMFm51bXB5Ll9jb3JlLm11bHRpYXJyYXmUjAxfcmVjb25zdHJ1Y3SUk5SMBW51bXB5lIwHbmRhcnJheZSTlEsAhZRDAWKUh5RSlChLAUsESwSGlGgDjAVkdHlwZZSTlIwCTziUiYiHlFKUKEsDjAF8lE5OTkr/////Sv////9LP3SUYoldlCiMEnN5bXB5LmNvcmUubnVtYmVyc5SMB0ludGVnZXKUk5SKCGTgnu/Yk+BihZSBlGgVigg5rHTzPrWCYoWUgZRoFYoImH7UmRiMnUWFlIGUaBWKCFlTxwaglr8uhZSBlGgVigkJ37Hl8U4qsQCFlIGUaBWKCAuKYDZqxOsOhZSBlGgVigkj1VgyO1xWzwCFlIGUaBWKCcLd9WCft2i7AIWUgZRoFYoJI2jLs3Ciu5gAhZSBlGgVigj+J0jZbbMjWIWUgZRoFYoJxkNGQV73xZEAhZSBlGgVigipSGebtyafCoWUgZRoFYoIeg6S/xmg1zeFlIGUaBWKCI+mP+J85/Q2hZSBlGgVigmysd++VGxozwCFlIGUaBWKCHKVTIkknI9lhZSBlGV0lGIu"))

B, iv, cipher = loads(b64decode("gASV+wEAAAAAAACMFm51bXB5Ll9jb3JlLm11bHRpYXJyYXmUjAxfcmVjb25zdHJ1Y3SUk5SMBW51bXB5lIwHbmRhcnJheZSTlEsAhZRDAWKUh5RSlChLAUsESwSGlGgDjAVkdHlwZZSTlIwCTziUiYiHlFKUKEsDjAF8lE5OTkr/////Sv////9LP3SUYoldlCiMEnN5bXB5LmNvcmUubnVtYmVyc5SMB0ludGVnZXKUk5SKCNTS9bC+wMoRhZSBlGgVigk4YpwsLyINqACFlIGUaBWKCaExxfooiXmaAIWUgZRoFYoIxOucKe4l13GFlIGUaBWKCSwSEXGbIOHAAIWUgZRoFYoIxqNCqxAPJCyFlIGUaBWKCPI0ZgsCoro5hZSBlGgVigk1OVgk4g9WrQCFlIGUaBWKCZALb4nYvHXNAIWUgZRoFYoJUm6Ox7DtKM4AhZSBlGgVigioe8g+29AiKoWUgZRoFYoIBlC25kdmJx+FlIGUaBWKCb7kZePWF6agAIWUgZRoFYoJ2+tDiqDHTLQAhZSBlGgVigiLn9MQMIzfeYWUgZRoFYoIuWDFjVHxSSyFlIGUZXSUYkMQuQYFxw3F4NTSq0WMk8o+LJRDMNdyWG4eH/iLX73CovdC1sj8UXrMHXbOOAUtsaomaFDNJkIyt9kNKDodI3pvl9ZVj5SHlC4="))

MS = MatrixSpace(GF(p), 4)

g = [[int(x) for x in row] for row in g]  
g = MS(g)  
g.set_immutable()  
A = [[int(x) for x in row] for row in A]  
A = MS(A)  
A.set_immutable()  
B = [[int(x) for x in row] for row in B]  
B = MS(B)  
B.set_immutable()

# a = discrete_log(A, g)  
a = 14694400667272  
C = B ** a

h = hashlib.sha256()  
h.update(str(np.array(C)).encode())  
digest = h.digest()

print(digest.hex(), iv.hex(), cipher.hex())  
```
