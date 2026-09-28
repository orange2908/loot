---
title: "X Marked the Spot - UIUCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "marked", "spot", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "For the challenge we were given and encrypted file and the encryption algorithm"
source:
  name: "CTFtime writeup #39299"
  url: "https://ctftime.org/writeup/39299"
original_source: "https://abdullahzamir.github.io/posts/UIUCTF-2024-X-Marked-the-Spot/"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "X Marked the Spot"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** X Marked the Spot
- **Author team:** zerox
- **CTFtime:** <https://ctftime.org/writeup/39299>
- **Original writeup:** <https://abdullahzamir.github.io/posts/UIUCTF-2024-X-Marked-the-Spot/>

---
<https://abdullahzamir.github.io/posts/UIUCTF-2024-X-Marked-the-Spot/>

For the challenge we were given and encrypted file and the encryption algorithm 

```python  
from itertools import cycle

flag = b"uiuctf{????????????????????????????????????????}"  
# len(flag) = 48  
key = b"????????"  
# len(key) = 8  
ct = bytes(x ^ y for x, y in zip(flag, cycle(key)))

with open("ct", "wb") as ct_file:  
ct_file.write(ct)

```

This is simple XOR, and we can retrieve the key using the association property of the XOR operation  
as we know some part of the plaintext, which is `uiuctf` and key is ok 8 charaters, to get the full key we only need to bruteforce one character

#### Solve Script:

```python

from itertools import cycle  
from pwn import xor 

f = open('ct','rb')  
flag = f.read()

pt = bytes.fromhex("uiuctf{".encode().hex())

key = xor(flag[:7],pt)

for i in range(0xff):  
key = key + bytes([i])  
pt = xor(flag,key)  
if b'uiuctf{' in pt:  
if b'}' in pt[len(pt)-1:]:  
print(pt)  
key = key[:-1]  
```
