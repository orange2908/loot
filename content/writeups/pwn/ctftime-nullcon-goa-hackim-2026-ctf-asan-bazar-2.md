---
title: "asan-bazar - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
type: "writeup"
tags: ["pwn", "aslr", "pie", "asan-bazar", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge provides a binary service (asan-bazaar) protected by AddressSanitizer (ASAN)."
source:
  name: "CTFtime writeup #40582"
  url: "https://ctftime.org/writeup/40582"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "asan-bazar"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** asan-bazar
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40582>

---
**Challenge Description**:  
The challenge provides a binary service (`asan-bazaar`) protected by AddressSanitizer (ASAN). The goal is to exploit it to read the flag.

**Analysis**:  
The binary has a vulnerability that allows an out-of-bounds write on the stack. By providing a specific "slot index" and an "adjustment", we can direct a write operation to the return address of the function on the stack.  
ASAN normally detects out-of-bounds accesses, but in specific stack layouts or with certain index calculations, it might be possible to skip over redzones or write to valid stack memory that happens to be the return address.  
The exploit uses a **partial overwrite** technique. Since the binary is PIE (Position Independent Executable), the higher bytes of the address are randomized, but the lower 12 bits are constant. We overwrite the lower 2 bytes of the return address with `0xbed0` to point it to a "win" function that prints the flag.

**Solution**:  
1\. Connect to the service.  
2\. Trigger the out-of-bounds write using slot index and adjustment.  
3\. Write 2 bytes: `0xbed0` (Little Endian `\xd0\xbe`).  
4\. Since we are overwriting 2 bytes (16 bits) and the ASLR randomization affects bits 12-15 (nibble), there is a probability involved. The script retries the connection until the base address aligns correctly and the `win` function is executed.

**Solver**: `pwn/asan_bazaar/[solve.py](http://solve.py)`

**Flag**: `ENO{COMPILING_WITH_ASAN_DOESNT_ALWAYS_MEAN_ITS_SAFE!!!}`
