---
title: "flag checker - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "checker", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "def reversetransformation(bytevalues):"
source:
  name: "CTFtime writeup #40035"
  url: "https://ctftime.org/writeup/40035"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "flag checker"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** flag checker
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40035>

---
```  
def reverse_transformation(byte_values):  
flag = bytearray(len(byte_values))  
  
for i in range(len(byte_values)):  
transformed_byte = byte_values[i]  
original_byte = ((transformed_byte << 5) & 0xFF) | (transformed_byte >> 3)  
flag[i] = (original_byte - i) ^ 0x5A  
  
return flag.decode('utf-8')

byte_2020 = [  
0xF8, 0xA8, 0xB8, 0x21, 0x60, 0x73, 0x90, 0x83, 0x80, 0xC3,  
0x9B, 0x80, 0xAB, 0x09, 0x59, 0xD3, 0x21, 0xD3, 0xDB, 0xD8,  
0xFB, 0x49, 0x99, 0xE0, 0x79, 0x3C, 0x4C, 0x49, 0x2C, 0x29,  
0xCC, 0xD4, 0xDC, 0x42  
]

flag = reverse_transformation(byte_2020)  
print(flag)  
```
