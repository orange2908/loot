---
title: "stack strings 2 - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "stack", "strings", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Similar to Stack Strings 1 but with a more complex verification loop."
source:
  name: "CTFtime writeup #40585"
  url: "https://ctftime.org/writeup/40585"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "stack strings 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** stack strings 2
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40585>

---
**Challenge Description**:  
Similar to Stack Strings 1 but with a more complex verification loop.

**Analysis**:  
The binary checks input length (41 chars) and then enters a loop that:  
1\. Computes a pseudo-random index `k` based on TEA and a permutation array.  
2\. Loads `input[k]`.  
3\. Updates a rolling accumulator `acc` using `input[k]` and a key byte.  
4\. Compares `acc` against a target value stored in another array.

**Solution**:  
1\. Dumped the permutation array (`0xa2`) and target array (`0xcb`) from memory using GDB.  
2\. Wrote a solver `[solve_stack2.py](http://solve_stack2.py)` that simulates the loop in reverse.  
3\. Since the initial accumulator state was unknown (derived from uninitialized memory or stack garbage), we brute-forced the single starting byte (256 possibilities) until the output contained `ENO`.

**Solver**: [[solve_stack2.py](http://solve_stack2.py)](file:///home/mritunjya/ctf/2026/nullcon/rev/stack_strings_2/[solve_stack2.py](http://solve_stack2.py))

**Flag**: `ENO{W0W_D1D_1_JU5T_UNLUCK_4_N3W_SK1LL???}`
