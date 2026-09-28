---
title: "Opalist - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "base64", "opalist", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40649"
  url: "https://ctftime.org/writeup/40649"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/Opalist/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Opalist"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Opalist
- **Author team:** RootRunners
- **CTFtime tags:** rev
- **CTFtime:** <https://ctftime.org/writeup/40649>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Reverse/Opalist/README.md>

---
# Opalist

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Reverse   
**Points:** 50 

**Files:** `challenge_final.impl`, `challenge_final.sign`, `OUTPUT.txt`

## Overview  
The runtime output shows a placeholder line and then a base64-like string. The actual program reads a line, transforms it with a pipeline of functions, and prints the transformed output. We only need to invert that pipeline on the observed output.

Observed output string:

```  
YnpYZVeGc45lc2VUZ05h  
```

The flag format is `ENO{DECODED_OUTPUT}`.

## Pipeline  
The program defines:

```  
cc = f14(bb)  
```

Where:  
\- `f3` applies a byte substitution `f1` to each character.  
\- `f4` converts characters to byte values.  
\- `f8` applies an index-based global shift to all bytes.  
\- `f13` encodes the result to base64.

So the output is `base64(f8(f4(f3(bb))))`.

## Inversion Strategy  
1\. Base64-decode the output to get the byte array `r`.  
2\. Invert `f8` by brute-forcing the global shift `S` in `[0..255]`:  
\- `f[i] = (r[i] - S) mod 256`  
\- Check that `S` matches the parity-based rule induced by `f`.  
3\. Build the inverse of the substitution `f1` from the `.impl` file and apply it to recover `bb`.

## Exploit Script  
```python  
#!/usr/bin/env python3  
import re  
import base64  
from pathlib import Path

IMPL_PATH = "challenge_final.impl"  
OUT_B64 = "YnpYZVeGc45lc2VUZ05h" # from OUTPUT.txt

def parse_f1_mapping(impl_text: str) -> dict[int, int]:  
"""  
Extract a -> b pairs from f1. For missing entries, f1 is the identity.  
"""  
m = re.search(r"FUN\s+f1\s*:[\s\S]*?FUN\s+f2", impl_text)  
if not m:  
raise ValueError("f1 block not found")  
f1_block = m.group(0)

pairs = re.findall(  
r"a\s*=\s*\\(\\("(\d+)"!\\)\\)\s*THEN\s*\\(\\("(\d+)"!\\)\\)",  
f1_block,  
)  
return {int(a): int(b) for a, b in pairs}

def build_inverse_f1(mapping: dict[int, int]) -> dict[int, int]:  
"""  
Build inv[b]=a on 0..255 and verify bijection.  
"""  
def f1(a: int) -> int:  
return mapping.get(a, a)

inv = {}  
for a in range(256):  
b = f1(a)  
if b in inv and inv[b] != a:  
raise ValueError(f"Collision: f1({inv[b]})=f1({a})={b}")  
inv[b] = a  
return inv

def invert_f8_from_r(r: list[int]) -> tuple[int, list[int]]:  
"""  
Find S such that:  
f[i] = (r[i]-S) mod 256  
and S is consistent with:  
S = sum q_l mod 256  
q_l = +l if f[l] even, -l if f[l] odd  
Returns (S, f_bytes).  
"""  
for S in range(256):  
f = [(ri - S) % 256 for ri in r]

total = 0  
for l, bl in enumerate(f):  
if (bl % 2) == 0:  
q = l % 256  
else:  
q = (-l) % 256  
total = (total + q) % 256

if total == S:  
return S, f

raise ValueError("No valid S found (f8 inversion failed)")

def main():  
impl = Path(IMPL_PATH).read_text(errors="replace")

mapping = parse_f1_mapping(impl)  
inv_f1 = build_inverse_f1(mapping)

data = base64.b64decode(OUT_B64)  
r = list(data)

S, fbytes = invert_f8_from_r(r)

bb_codes = [inv_f1[b] for b in fbytes]  
bb = bytes(bb_codes).decode("latin1")

print("[+] base64 decoded (r):", data.hex())  
print("[+] found S:", S)  
print("[+] recovered input (bb):", bb)  
print("[+] FLAG:", f"ENO{{{bb}}}")

if __name__ == "__main__":  
main()  
```

## Flag  
`ENO{R3v_0p4L_4_FuN!}`
