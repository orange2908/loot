---
title: "flag checker - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "checker", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The binary expects a 34-character flag."
source:
  name: "CTFtime writeup #39953"
  url: "https://ctftime.org/writeup/39953"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "flag checker"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** flag checker
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39953>

---
# Flag Checker

The binary expects a 34-character flag.  
For each character at index i, the binary performs:

```  
temp = (input[i] ^ 0x5A) + i;  
encoded_byte = ROTL(temp, 3);   
```

The resulting array of 34 encoded bytes is compared against a constant array:  
```  
F8 A8 B8 21 60 73 90 83 80 C3 9B 80 AB 09 59 D3 21 D3 DB D8  
FB 49 99 E0 79 3C 4C 49 2C 29 CC D4 DC 42  
```

Python exploit to get flag

```  
def ror(val, r_bits, max_bits=8):  
return ((val >> r_bits) | (val << (max_bits - r_bits))) & ((1 << max_bits) - 1)

target = [  
0xF8, 0xA8, 0xB8, 0x21, 0x60, 0x73, 0x90, 0x83, 0x80, 0xC3,  
0x9B, 0x80, 0xAB, 0x09, 0x59, 0xD3, 0x21, 0xD3, 0xDB, 0xD8,  
0xFB, 0x49, 0x99, 0xE0, 0x79, 0x3C, 0x4C, 0x49, 0x2C, 0x29,  
0xCC, 0xD4, 0xDC, 0x42  
]

flag = ""

for i, enc_byte in enumerate(target):  
T = ror(enc_byte, 3)  
orig = ((T - i) & 0xFF) ^ 0x5A  
flag += chr(orig)

print(flag)

```

```  
ENO{R3V3R53_3NG1N33R1NG_M45T3R!!!}  
```
