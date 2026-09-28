---
title: "stack strings 1 - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "xor", "pie", "stack", "strings", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40647"
  url: "https://ctftime.org/writeup/40647"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/stack_strings_1/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "stack strings 1"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** stack strings 1
- **Author team:** RootRunners
- **CTFtime tags:** rev
- **CTFtime:** <https://ctftime.org/writeup/40647>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/stack_strings_1/README.md>

---
# Stack strings 1

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Reverse   
**Points:** 50 

**Files:** `stackstrings_med`

## Overview  
The binary is stripped and PIE. It mmap()s a blob from `.rodata`, deobfuscates it with XORs, then uses the blob to validate the input. Recreating the checks yields the exact input string.

## Key Insight  
The expected length and constants are stored in the deobfuscated blob. The verification loop computes two low-byte values and XORs them to derive the required input byte at each position. Reimplementing the loop recovers the flag directly.

## Solution  
1\. Extract the `.rodata` blob and apply the same XOR deobfuscation seen in the disassembly.  
2\. Recover the expected length and constants from the blob.  
3\. Reimplement the byte-by-byte loop and reconstruct the input.

## Requirements  
\- Python 3  
\- `pyelftools` for `.rodata` extraction

## Exploit Script  
```python  
#!/usr/bin/env python3  
from pathlib import Path  
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
return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))

BIN = "stackstrings_med"  
# Stack strings 1  
BLOB_VADDR = 0x20D0  
BLOB_LEN = 0xBD

blob = rodata_slice(BIN, BLOB_VADDR, BLOB_LEN)

length = blob[0xB8] ^ 0x36

b9, bA, bB, bC = blob[0xB9], blob[0xBA], blob[0xBB], blob[0xBC]  
r15 = ((bC ^ 0x0A) << 24) | ((bB ^ 0xC7) << 16) | ((bA ^ 0x95) << 8) | (b9 ^ 0x19)

expected = blob[0x95 : 0x95 + length]

def f1_low(ebx, i):  
esi = (ebx ^ 0xC19EF49E) & 0xFFFFFFFF  
esi = rol32(esi, i & 7)  
ecx = ((esi >> 16) ^ esi) & 0xFFFFFFFF  
esi2 = ((ecx >> 8) ^ ecx) & 0xFFFFFFFF  
return esi2 & 0xFF

def f2_low(eax, r9):  
edx = (eax ^ r15) & 0xFFFFFFFF  
edx = rol32(edx, r9 & 7)  
ecx = ((edx >> 15) ^ edx) & 0xFFFFFFFF  
edx2 = ((ecx >> 7) ^ ecx) & 0xFFFFFFFF  
return edx2 & 0xFF

inp = []  
eax = 0xA97288ED  
ebx = 0x9E3779B9  
r9 = 0

for i in range(length):  
sil = f1_low(ebx, i) ^ expected[i]  
dl_pre = f2_low(eax, r9)  
inp.append(dl_pre ^ sil)  
eax = (eax + 0x85EBCA6B) & 0xFFFFFFFF  
ebx = (ebx + 0x9E3779B9) & 0xFFFFFFFF  
r9 = (r9 + 3) & 0xFFFFFFFF

flag = bytes(inp).decode("latin1")  
print(flag)  
```

## Flag  
`ENO{1_L0V3_R3V3R51NG_5T4CK_5TR1NG5}`
