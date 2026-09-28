---
title: "Opalist - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "substitution-cipher", "base64", "opalist", "classical", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Given output from a program written in Opal (a functional language), decode it to recover the flag."
source:
  name: "CTFtime writeup #40588"
  url: "https://ctftime.org/writeup/40588"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Opalist"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Opalist
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40588>

---
**Challenge Description**:  
Given output from a program written in Opal (a functional language), decode it to recover the flag.

**Analysis**:  
The challenge provides:  
\- `challenge_final.impl`: Source code in Opal language  
\- `OUTPUT.txt`: Shows Base64-encoded output `YnpYZVeGc45lc2VUZ05h`

The Opal program performs:  
1\. `f1`: Substitution cipher (char → char mapping)  
2\. `f3`: Applies `f1` to each character  
3\. `f4`: Converts string to sequence of nats  
4\. `f8`: Accumulator-based transform with `f6` (even/odd multiplier)  
5\. `f13`: Base64 encoding

**Solution**:  
1\. Decode Base64 to get intermediate bytes  
2\. Brute-force the accumulator sum `S` (0-255) to invert `f8`  
3\. Invert the substitution cipher `f1`

**Solver**: [[solve_opalist.py](http://solve_opalist.py)](file:///home/mritunjya/ctf/2026/nullcon/rev/opalist/[solve_opalist.py](http://solve_opalist.py))

**Flag**: `ENO{R3v_0p4L_4_FuN!}`
