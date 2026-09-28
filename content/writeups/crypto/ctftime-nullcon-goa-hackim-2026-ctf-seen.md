---
title: "Seen - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "seen", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge provided an index.html file containing an input field and a Javascript snippet that checks the flag."
source:
  name: "CTFtime writeup #40574"
  url: "https://ctftime.org/writeup/40574"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Seen"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Seen
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40574>

---
**Challenge Description**:  
The challenge provided an `index.html` file containing an input field and a Javascript snippet that checks the flag.

**Analysis**:  
The script contained a string `s` made of Variation Selector characters.  
```javascript  
const s="︍︃︁️︇︁︋︂︌︅︀︀︁︄︀︆︇︃︋︅︄︂︎︈︆︌︅︅︁︆︍︎︎︉︌︃︂︄︌︇️︅️︈︂︎︍︉︋︋︁︍︂︋︇︍︋︄︆︀︀︄︎︎︇︀︋︍︍︍︈︇︌︈︅︁︍︉︆︍️︅︁︀︉︂︀︈️︄︆︆︎︍︁︇︉︎︁︋️︇︆︎️︌︀︄︀︂️︌︆︎️︅︇︈︈︇︁︎︈︌︀︊️︅︇︃︈︍︀︎︈︄︇︀︉︌︇︈︍︀";  
```  
It decodes this string into an integer array `t` by taking pairs of characters and combining their values (shifted by `0xFE00`).  
The validation logic iterates through the input flag `u`, updating a 32-bit generator `gen`:  
```javascript  
gen=((gen^0xA7012948^u[i])+131203)&0xffffffff;  
if(t[u.length+i]!==(gen%256+256)%256) return "wrong";  
```

**Solution**:  
The check is reversible. Since `gen` depends on the previous `gen` and the current flag byte `u[i]`, and the result is checked against a known value `t[...]`, we can solve for `u[i]`.  
We wrote a solver script that:  
1\. Extracts and decodes `t` from the HTML.  
2\. Reconstructs `u[i]` byte-by-byte using the inverse operations: `u[i] = ((target - const_add) & 0xFF) ^ (prev_gen & 0xFF) ^ (const_xor & 0xFF)`.

**Solver**: [[solve_seen.py](http://solve_seen.py)](file:///home/mritunjya/ctf/2026/nullcon/misc/seen/[solve_seen.py](http://solve_seen.py))

**Flag**: `ENO{W0W_1_D1DN'T_533_TH4T_C0M1NG!!!}`
