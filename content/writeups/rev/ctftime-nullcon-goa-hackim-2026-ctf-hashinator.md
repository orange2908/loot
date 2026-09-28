---
title: "Hashinator - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "subprocess", "regex", "hashinator", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40643"
  url: "https://ctftime.org/writeup/40643"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/Hashinator/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Hashinator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Hashinator
- **Author team:** RootRunners
- **CTFtime tags:** rev
- **CTFtime:** <https://ctftime.org/writeup/40643>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/Hashinator/README.md>

---
# Hashinator

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Reverse   
**Points:** 89 

**Files:** `challenge_final`, `OUTPUT.txt`

## Overview  
The binary prints a 32-hex digest per line. The log contains 54 digests, and running the binary with different inputs shows that only the last digest changes when the last character changes. This means the program hashes every prefix of the input.

## Key Insight  
If the output is `hash(prefix[0])`, `hash(prefix[1])`, ... then we can recover the input one character at a time. For prefix length `i`, we try all characters and run the binary; the correct character is the one whose prefix hash matches the `i`-th line in `OUTPUT.txt`.

## Solution  
1\. Count digests in `OUTPUT.txt` to get the flag length (54 digests -> 53 characters).  
2\. For each position `i`, brute-force one character and compare the `i`-th digest.  
3\. Use a limited charset to keep the search fast.

## Exploit Script  
```python  
#!/usr/bin/env python3  
import re  
import string  
import subprocess  
from pathlib import Path

BIN = Path("challenge_final")  
OUT = Path("OUTPUT.txt")

hashes = [  
ln.strip()  
for ln in OUT.read_text().splitlines()  
if re.fullmatch(r"[0-9a-f]{32}", ln.strip())  
]

charset = string.ascii_letters + string.digits + "_{}!?-"

def run_full(s: str):  
return subprocess.check_output([str(BIN)], input=s.encode()).decode().splitlines()

def hash_prefix(prefix: str, plen: int):  
L = max(15, plen)  
s = prefix + "A" * max(0, L - len(prefix))  
outs = run_full(s)  
return outs[plen]

prefix = ""  
for plen in range(1, len(hashes)):  
want = hashes[plen]  
for ch in charset:  
cand = prefix + ch  
if hash_prefix(cand, plen) == want:  
prefix = cand  
break  
else:  
raise RuntimeError("Character not found")

print(prefix)  
```

## Flag  
`ENO{MD2_1S_S00_0ld_B3tter_Implement_S0m3Th1ng_ElsE!!}`
