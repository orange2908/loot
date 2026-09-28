---
title: "Powerplay - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "powerplay", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This is involving getting negative index of the list by exploiting squaring a positive number in np.int32 to give a negative number."
source:
  name: "CTFtime writeup #39933"
  url: "https://ctftime.org/writeup/39933"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Powerplay"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Powerplay
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39933>

---
This is involving getting negative index of the list by exploiting squaring a positive number in `np.int32` to give a negative number.  
We could simply brute force it  
```python=  
from gmpy2 import iroot  
for i in range(0, 200000000):  
offset = i * 0x100000000 + 0xffffffff + 1  
for j in range(1, 25):  
if iroot(offset - j, 2)[1]:  
print('i', i, j)  
# 280614  
raise  
```  
then send a single value `iroot(280614 * 0x100000000 + 0xffffffff + 1 - 0, 2)[0]`.
