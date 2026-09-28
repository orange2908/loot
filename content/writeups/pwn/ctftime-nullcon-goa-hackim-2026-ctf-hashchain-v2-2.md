---
title: "hashchain v2 - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcode", "aslr", "hashchain", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge involves a service where the MD5 hash of our input is executed as shellcode."
source:
  name: "CTFtime writeup #40633"
  url: "https://ctftime.org/writeup/40633"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "hashchain v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** hashchain v2
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40633>

---
**Challenge Description**:  
The challenge involves a service where the MD5 hash of our input is executed as shellcode. The binary also prints the address of a "win" function, but ASLR is enabled, meaning this address changes every run.

**Analysis**:  
Since the shellcode is derived from the MD5 hash of our input, we cannot easily construct arbitrary shellcode (we need to find a preimage that hashes to specific bytes).  
The goal is to jump to the "win" function. A simple shellcode to do this is `push <win_addr>; ret`.  
However, because of ASLR, the win address allows for randomization.

**Solution**:  
Instead of trying to find a new MD5 collision for every new win address (which is too slow), we found a single "magic string" whose MD5 hash corresponds to valid `push <address>; ret` instructions for a *specific* address.  
\- **Magic String**: `kkcKyJFCo`  
\- **MD5 Hash**: `68 5d 32 5d 56 c3 ...`  
\- **Disassembly**:  
```assembly  
push 0x565d325d  
ret  
```  
This shellcode jumps to `0x565d325d`.  
We then run the exploit in a loop, constantly sending this magic string. We rely on the probability that ASLR will eventually align the "win" function to `0x565d325d`. When it does, our payload successfully jumps to it and we get the flag.  
**Flag**: `ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}`
