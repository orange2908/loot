---
title: "flagprinter - CyberSpace CTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "recursive", "flagprinter", "cyberspace-ctf", "cyberspace-ctf-2024", "2024", "ctf-writeup"]
summary: "return recur(r // 3) + r % 3"
source:
  name: "CTFtime writeup #39432"
  url: "https://ctftime.org/writeup/39432"
original_source: "https://github.com/Team-Kirby/csctf-2024-writeups/blob/main/crypto/flagprinter/solve.py"
ctf:
  name: "CyberSpace CTF 2024"
  year: 2024
  challenge: "flagprinter"
---

## Metadata

- **CTF:** CyberSpace CTF 2024
- **Task:** flagprinter
- **Author team:** Team Kirby
- **CTFtime tags:** crypto, recursive
- **CTFtime:** <https://ctftime.org/writeup/39432>
- **Original writeup:** <https://github.com/Team-Kirby/csctf-2024-writeups/blob/main/crypto/flagprinter/solve.py>

---
``` python3

from out import enc, R  
from math import prod

flag = ''

# a is a long array that goes by   
# First iteration: [0, 1, 2]  
# Second iteration: [0, 1, 2, 1, 2, 3, 2, 3, 4]  
# It goes on...  
# As you can see, the length of a is in the multiple of 3s and each "subsection" starts off from its index in the subsection increments e.g. 1, 2, 3, 4..  
# This can be solved with a simple recursion function

def recur(r):  
if r // 3 == 0:  
return r % 3

return recur(r // 3) + r % 3

for i in range(len(enc)):  
flag += chr(enc[i] ^ prod([recur(_) for _ in R[i]]))  
print(flag)

```
