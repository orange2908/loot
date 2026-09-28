---
title: "stack strings 1 - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "stack", "strings", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "A binary asking for a \"member code\"."
source:
  name: "CTFtime writeup #40586"
  url: "https://ctftime.org/writeup/40586"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "stack strings 1"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** stack strings 1
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40586>

---
**Challenge Description**:  
A binary asking for a "member code".

**Analysis**:  
The binary reads input character by character and checks for a newline. A length check at `0x13bd` enforces a specific input length (found to be 35 via debugging).  
The input is then validated by a TEA-like checksum loop. The "expected" checksums are stored in stack strings (constructed at runtime).

**Solution**:  
1\. Debugged with GDB to find the expected length (35).  
2\. Dumped the "expected" comparison bytes from memory (`r14+0x95`) and the TEA parameters (`eax`, `ebx`, `r15`).  
3\. Wrote a solver `[solve_stack1.py](http://solve_stack1.py)` to reverse the transformation: `Input[i] ^ KeyStream[i] == Expected[i]`.

**Solver**: [[solve_stack1.py](http://solve_stack1.py)](file:///home/mritunjya/ctf/2026/nullcon/rev/stack_strings_1/[solve_stack1.py](http://solve_stack1.py))

**Flag**: `ENO{1_L0V3_R3V3R51NG_5T4CK_5TR1NG5}`
