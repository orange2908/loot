---
title: "Matrixfun - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "sage", "discrete-log", "matrixfun", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This challenge involves solving a matrix-based discrete logarithm problem (DLP) and then using the solution to decrypt an AES-encrypted ciphertext to obtain the flag."
source:
  name: "CTFtime writeup #40007"
  url: "https://ctftime.org/writeup/40007"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Matrixfun"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Matrixfun
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40007>

---
# crypto/Matrixfun

This challenge involves solving a matrix-based discrete logarithm problem (DLP) and then using the solution to decrypt an AES-encrypted ciphertext to obtain the flag. To recover the secret key we can simply use Baby Step Giant Step algorithm for matrix dlp since the order was only 49 bits long.  
The following is a snippet of sage code that implements the matrix dlp:

```py

def bsgs(g, h, order):  
m = ceil(sqrt(order))

alpha = identity_matrix(F, 4)  
table = {}  
for i in tqdm(range(m)):  
hash = sha256(str(alpha).encode()).digest()  
alpha = alpha * G  
table[int.from_bytes(hash, "big")] = i

gm = g ** (-m)  
gmj = identity_matrix(F, 4)  
for j in tqdm(range(m)):  
y = h * gmj  
gmj = gmj * gm  
hash = sha256(str(y).encode()).digest()  
hash = int.from_bytes(hash, "big")  
if hash in table:  
return j * m + table[hash]  
return None

a = bsgs(G, A, gorder)  
print(a)  
assert G ** a == A  
```

We can then use the recovered secret key to find the shared secret and decrypt the message which turns out to be the flag.
