---
title: "Say My Name - CTF@CIT 2026"
category: "rev"
type: "writeup"
tags: ["rev", "re", "strings", "say", "name", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "We’re given a statically linked 64-bit ELF binary named saymyname that is not stripped."
source:
  name: "CTFtime writeup #40772"
  url: "https://ctftime.org/writeup/40772"
original_source: "https://ctftime.org/team/431287"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Say My Name"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Say My Name
- **Author team:** Echelon Obscura
- **CTFtime tags:** re, strings
- **CTFtime:** <https://ctftime.org/writeup/40772>
- **Original writeup:** <https://ctftime.org/team/431287>

---
### Say My Name (Reversing) - CTF@CIT 2026  
We’re given a statically linked 64-bit ELF binary named `saymyname` that is not stripped.

#### Solution  
Getting the flag for this challenge was straightforward. I simply ran the `strings` command on the binary and piped the output to `grep`, filtering based on the known flag format:  
```bash  
$ strings saymyname | grep "CIT"  
yeah that me. heres your flag CIT{Zn583Umnwd4S}  
```
