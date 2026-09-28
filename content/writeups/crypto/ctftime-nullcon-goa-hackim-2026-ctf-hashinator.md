---
title: "Hashinator - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "hashinator", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "A binary challengefinal that reads a string and outputs hashes."
source:
  name: "CTFtime writeup #40583"
  url: "https://ctftime.org/writeup/40583"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Hashinator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Hashinator
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40583>

---
**Challenge Description**:  
A binary `challenge_final` that reads a string and outputs hashes. We are provided with `OUTPUT.txt` containing 54 hashes (32-hex chars each).

**Analysis**:  
1\. **Static Analysis**: The binary is statically linked and stripped. Strings analysis revealed `Achallenge_Afinal` symbols, suggesting it was compiled with the Opal Compiler (OCS) or a similar functional language runtime.  
2\. **Behavioral Analysis**: Running the binary with different inputs revealed that the output hashes change based on the input characters. Specifically, the $i$-th input character affects the $(i+2)$-th hash.  
3\. **Hash Verification**: Simple MD5/SHA verification of single characters failed. The hashes appear to be MD2 (hinted by the flag `MD2_1S...`), but we treated the binary as a black-box oracle.

**Solution**:  
1\. We observed that the binary can be used as an oracle. Since there is a direct correlation between the $i$-th input character and the $(i+2)$-th hash, we can brute-force the flag character-by-character.  
2\. We wrote a solver script `[solve.py](http://solve.py)` that iterates through printable characters, constructs a candidate flag, runs the binary, and checks if the corresponding hash matches the target hash in `OUTPUT.txt`.  
3\. This efficiently recovered the flag one character at a time.

**Solver**: [[solve.py](http://solve.py)](file:///home/mritunjya/ctf/2026/nullcon/rev/hashinator/[solve.py](http://solve.py))

**Flag**: `ENO{MD2_1S_S00_0ld_B3tter_Implement_S0m3Th1ng_ElsE!!}`
