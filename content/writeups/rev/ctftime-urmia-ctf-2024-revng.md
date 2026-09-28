---
title: "REVNG - Urmia CTF 2024"
category: "rev"
type: "writeup"
tags: ["rev", "reverse", "engineering", "revng", "urmia-ctf", "urmia-ctf-2024", "2024", "ctf-writeup"]
summary: "charset = string.printable"
source:
  name: "CTFtime writeup #39456"
  url: "https://ctftime.org/writeup/39456"
original_source: "https://youtu.be/cc-FYlChsS8"
ctf:
  name: "Urmia CTF 2024"
  year: 2024
  challenge: "REVNG"
---

## Metadata

- **CTF:** Urmia CTF 2024
- **Task:** REVNG
- **Author team:** ResetSec
- **CTFtime tags:** reverse, engineering
- **CTFtime:** <https://ctftime.org/writeup/39456>
- **Original writeup:** <https://youtu.be/cc-FYlChsS8>

---
# Solution  
```python  
import string

charset = string.printable  
eq = lambda a, b : (a << ((8 - b) & 0x1f)) | (a >> (b & 0x1f))  
random_values = [  
0x22, 0x0d, 0x1e, 0x0c, 0x12, 0x0b, 0x0a, 0x27, 0x18, 0x10, 0x02,  
0x00, 0x14, 0x1c, 0x0e, 0x01, 0x06, 0x13, 0x09, 0x08, 0x20, 0x1d,  
0x16, 0x29, 0x11, 0x25, 0x04, 0x23, 0x05, 0x24, 0x26, 0x1a, 0x28,  
0x07, 0x1f, 0x19, 0x03, 0x21, 0x0f, 0x15, 0x1b, 0x17  
]

with open('./flag.enc', 'rb') as f:  
enc = f.read()

for i in range(len(enc) - 4):  
for c in charset:  
if eq(ord(c) ^ random_values[i], 5) & 0xff == enc[i]:  
print(c, end='')

print()  
```

# Explanation  
<https://youtu.be/cc-FYlChsS8>
