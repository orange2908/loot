---
title: "sess.io - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "sess", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "I noticed that the session cookie only depends on the seed (so the flag), so first I generated multiple hashes to get all 10 possible sessions cookies."
source:
  name: "CTFtime writeup #40029"
  url: "https://ctftime.org/writeup/40029"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "sess.io"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** sess.io
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40029>

---
Solved by V0odOo

I noticed that the session cookie only depends on the seed (so the flag), so first I generated multiple hashes to get all 10 possible sessions cookies.

```python  
import hashlib

ids = []  
hashes = []

i = 0  
while len(ids) < 10:  
h = hashlib.md5(b"0" + str(i).encode()).hexdigest()  
if h[0] == str(len(ids)):  
ids.append("0" + str(i))  
hashes.append(h)  
i += 1

print(ids)  
print(hashes)  
```

Then as each seed is only 4 bytes of the flag, I computed every possible session cookie to see which ones matched the ones we got from the server -> we get the 10 seeds (so we get the flag)

```

```
