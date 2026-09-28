---
title: "stack strings 2 - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "stack", "strings", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40646"
  url: "https://ctftime.org/writeup/40646"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/stack_strings_2/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "stack strings 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** stack strings 2
- **Author team:** RootRunners
- **CTFtime tags:** rev
- **CTFtime:** <https://ctftime.org/writeup/40646>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/stack_strings_2/README.md>

---
# Stack strings 2

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Reverse   
**Points:** 50 

**Files:** `stackstrings_hard`

## Overview  
The binary copies a `.rodata` blob into an mmap buffer, XORs it, then uses it to validate the input. The validation loop permutes positions and depends on the previous character, so the input is reconstructed by emulating the loop.

## Key Insight  
All constants and lookup bytes are embedded in the deobfuscated buffer. By reimplementing the loop, we can compute the required byte for each position and place it at the correct index.

## Solution  
1\. Extract and deobfuscate the `.rodata` blob (as done in the binary).  
2\. Recover `len`, `r15`, and the initial state byte from the blob.  
3\. Emulate the loop to compute each byte and write it to `input[pos]`.

## Requirements  
\- Python 3  
\- `pyelftools` for `.rodata` extraction

## Exploit Script  
```python  
#!/usr/bin/env python3  
from elftools.elf.elffile import ELFFile

def rodata_slice(path: str, vaddr: int, size: int) -> bytes:  
with open(path, "rb") as f:  
elf = ELFFile(f)  
ro = elf.get_section_by_name(".rodata")  
base = ro["sh_addr"]  
off = vaddr - base  
return ro.data()[off : off + size]

def rol32(x, r):  
r &= 31  
x &= 0xFFFFFFFF  
return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def rol8(x, r=1):  
x &= 0xFF  
r &= 7  
return ((x << r) | (x >> (8 - r))) & 0xFF

BIN = "stackstrings_hard"  
# Stack strings 2  
BLOB_VADDR = 0x20E0  
BLOB_LEN = 0xFA

buf = bytearray(rodata_slice(BIN, BLOB_VADDR, BLOB_LEN))

L = buf[0xF4] ^ 0xA7  
r15 = (  
((buf[0xF8] ^ 0x13) << 24)  
| ((buf[0xF7] ^ 0x4B) << 16)  
| ((buf[0xF6] ^ 0xD3) << 8)  
| (buf[0xF5] ^ 0x3A)  
)  
state = (buf[0xF9] ^ 0x77) & 0xFF

edx = 0x9E3779B9  
r10 = 0xA97288ED  
r9 = 0  
inp = [None] * L

for i in range(L):  
ecx = i & 7  
esi = (edx ^ 0xEC8804A0) & 0xFFFFFFFF  
esi = rol32(esi, ecx)  
eax = ((esi >> 16) ^ esi) & 0xFFFFFFFF  
esi2 = ((eax >> 8) ^ eax) & 0xFFFFFFFF  
sil = (esi2 & 0xFF) ^ buf[0xA2 + i]  
pos = sil

eax2 = (edx ^ 0x19E0463B) & 0xFFFFFFFF  
eax2 = rol32(eax2, ecx)  
ecx2 = ((eax2 >> 16) ^ eax2) & 0xFFFFFFFF  
eax3 = ((ecx2 >> 8) ^ ecx2) & 0xFFFFFFFF  
al = (eax3 & 0xFF) ^ buf[0xCB + i]

esi3 = (r10 ^ r15) & 0xFFFFFFFF  
esi3 = rol32(esi3, r9 & 7)  
ecx3 = ((esi3 >> 15) ^ esi3) & 0xFFFFFFFF  
esi4 = ((ecx3 >> 7) ^ ecx3) & 0xFFFFFFFF  
sil2_base = esi4 & 0xFF

need = (al - rol8(state, 1)) & 0xFF  
cur = sil2_base ^ need

inp[pos] = cur  
state = cur

r9 = (r9 + 3) & 0xFFFFFFFF  
r10 = (r10 + 0x85EBCA6B) & 0xFFFFFFFF  
edx = (edx + 0x9E3779B9) & 0xFFFFFFFF

flag = bytes(inp).decode("latin1")  
print(flag)  
```

## Flag  
`ENO{W0W_D1D_1_JU5T_UNLUCK_4_N3W_SK1LL???}`
