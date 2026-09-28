---
title: "hashchain v2 - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
type: "writeup"
tags: ["pwn", "hashchain", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40641"
  url: "https://ctftime.org/writeup/40641"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/hashchain_v2/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "hashchain v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** hashchain v2
- **Author team:** RootRunners
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/40641>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/hashchain_v2/README.md>

---
# hashchain v2

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** PWN   
**Points:** 365   
**Service:** `52.59.124.14:5011`

## Overview  
Hashes are stored at user-controlled offsets and the resulting buffer is executed as x86 code. The service prints the `win()` address on connect. We build a 3-hash chain that implements:

```  
jmp +2  
push win  
ret  
```

This requires MD5 preimages whose first bytes match the needed opcodes.

## Working Inputs  
\- Jump hash (produces `EB 02`): `143874`  
\- Ret hash (produces `?? C3` with `56 C3`): `5488`  
\- Push hash: precomputed map of values producing `68 5d XX XX` where `XX XX` match the current `win()` address bytes.

Example winning address:  
```  
win() = 0x5656c25d  
```  
Required bytes (little endian): `5d c2 56 56`, so we need an MD5 starting with `68 5d c2 56`. One match is input `158503222`.

## Exploit Flow  
1\. Connect and read the printed `win()` address.  
2\. Send `143874` (offset 0).  
3\. Send matching push-hash input (offset 4).  
4\. Send `5488` (offset 8).  
5\. Send `doit` to execute.

## Flag  
`ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}`
