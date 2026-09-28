---
title: "atomizer - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcode", "atomizer", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge provides a binary service (== BUG ATOMIZER ==) that asks for a \"mixture\" of pesticide drops."
source:
  name: "CTFtime writeup #40587"
  url: "https://ctftime.org/writeup/40587"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "atomizer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** atomizer
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40587>

---
**Challenge Description**:  
The challenge provides a binary service (`== BUG ATOMIZER ==`) that asks for a "mixture" of pesticide drops. The service takes user input and, if the length and content conditions are met, executes it.

**Analysis**:  
The binary reads user input into a buffer and executes it as shellcode. However, there is a strict length constraint: the input must be exactly 69 bytes long. If the input is too short or too long, the "sprayer" won't work.

**Solution**:  
1\. Construct a standard `execve("/bin/sh", 0, 0)` shellcode (typically ~27-30 bytes for x64).  
2\. Pad the shellcode with dummy bytes (e.g., 'A') to reach exactly 69 bytes.  
3\. Send the payload to the service. The service executes the buffer, granting a shell.

**Flag**: `ENO{GIVE_ME_THE_RIGHT_AMOUNT_OF_ATOMS_TO_WIN}`
