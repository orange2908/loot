---
title: "emoji - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "emoji", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge provided a README.md file containing a sequence of emojis and hidden characters."
source:
  name: "CTFtime writeup #40614"
  url: "https://ctftime.org/writeup/40614"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "emoji"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** emoji
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40614>

---
**Challenge Description**:  
The challenge provided a `[README.md](http://README.md)` file containing a sequence of emojis and hidden characters.

**Analysis**:  
Inspecting `[README.md](http://README.md)` with a python script revealed characters in the Variation Selector Supplement block (`U+E0100` - `U+E01EF`).  
The characters were found to be offset by `0xE00F0` from standard ASCII characters.

**Solution**:  
A Python script was created to read the file, filter for characters in the target range, and subtract the offset to reveal the flag.

**Solver**: [[solve.py](http://solve.py)](file:///home/mritunjya/ctf/2026/nullcon/misc/emoji/[solve.py](http://solve.py))

**Flag**: `ENO{EM0J1S_UN1COD3_1S_MAG1C}`
