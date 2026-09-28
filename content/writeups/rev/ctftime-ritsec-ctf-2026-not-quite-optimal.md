---
title: "not quite optimal - RITSEC CTF 2026"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "number-theory", "power-towers", "re", "ghidra", "proof-of-work", "static-analysis", "ritsec-ctf", "ritsec-ctf-2026", "2026", "ctf-writeup"]
summary: "We’re given a stripped 64-bit ELF that computes the flag through a recursive function."
source:
  name: "CTFtime writeup #40703"
  url: "https://ctftime.org/writeup/40703"
original_source: "https://ctftime.org/team/431287"
ctf:
  name: "RITSEC CTF 2026"
  year: 2026
  challenge: "not quite optimal"
---

## Metadata

- **CTF:** RITSEC CTF 2026
- **Task:** not quite optimal
- **Author team:** Echelon Obscura
- **CTFtime tags:** number_theory, power_towers, re
- **CTFtime:** <https://ctftime.org/writeup/40703>
- **Original writeup:** <https://ctftime.org/team/431287>

---
### not quite optimal (Reversing) - RITSEC CTF 2026  
We’re given a stripped 64-bit ELF that computes the flag through a recursive function. No symbols, so straight into Ghidra.

#### Approach

Looking at `main`, the program:  
1\. Requires three specific inputs (`looking for the flag`, `please` and `PLEASE MAY I HAVE THE FLAG`)  
1\. Wipes the input buffer between stages  
1\. Calls a function to compute the flag character-by-character

Instead of storing the flag, each character is generated dynamically using a function that I called `compute_flag_char`.

Inside this function:  
1\. A delay is introduced using `nanosleep` (increasing per character)  
1\. A GMP-based function is called to compute the actual value

Following the call chain leads to a function that builds **power towers** (tetration):  
1\. Computes values of the form `base^(base^(...))`  
1\. Uses arbitrary-precision arithmetic (GMP)  
1\. Reduces the result mod 256  
1\. Applies `(value + 1) >> 1` to produce the final character

Trying to run this directly is not practical, because:  
1\. The delay grows quickly  
1\. The power tower computation becomes extremely expensive

So instead of executing the binary, the goal is to **replicate the logic efficiently**.

#### Solution Script  
```python  
#!/usr/bin/env python3  
import struct, sys

raw = "02 00 00 00 00 00 00 00 75 2b 19 00 00 00 00 00 02 00 00 00 00 00 00 00 c5 95 32 00 00 00 00 00 02 00 00 00 00 00 00 00 97 0b 38 00 00 00 00 00 02 00 00 00 00 00 00 00 cd 32 4b 00 00 00 00 00 02 00 00 00 00 00 00 00 27 4a 64 00 00 00 00 00 02 00 00 00 00 00 00 00 d1 a6 6e 00 00 00 00 00 02 00 00 00 00 00 00 00 17 2a 7a 00 00 00 00 00 02 00 00 00 00 00 00 00 17 ea 8c 00 00 00 00 00 02 00 00 00 00 00 00 00 27 d5 a7 00 00 00 00 00 02 00 00 00 00 00 00 00 35 a4 b9 00 00 00 00 00 02 00 00 00 00 00 00 00 cd fe c1 00 00 00 00 00 02 00 00 00 00 00 00 00 1b 70 d8 00 00 00 00 00 02 00 00 00 00 00 00 00 d1 bc e7 00 00 00 00 00 02 00 00 00 00 00 00 00 7d 80 f8 00 00 00 00 00 02 00 00 00 00 00 00 00 cd b8 05 01 00 00 00 00 02 00 00 00 00 00 00 00 9f 01 19 01 00 00 00 00 02 00 00 00 00 00 00 00 d3 65 2d 01 00 00 00 00 02 00 00 00 00 00 00 00 cd 7f 37 01 00 00 00 00 02 00 00 00 00 00 00 00 43 d4 4a 01 00 00 00 00 02 00 00 00 00 00 00 00 a9 c5 5d 01 00 00 00 00 02 00 00 00 00 00 00 00 99 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 3b 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 f5 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 1b 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 0d 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 97 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 2f 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 f5 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 9f 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 1b 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 f1 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 0d 02 00 00 00 00 00 00 03 00 00 00 00 00 00 00 e3 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 f5 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 53 02 00 00 00 00 00 00 03 00 00 00 00 00 00 00 f5 01 00 00 00 00 00 00 03 00 00 00 00 00 00 00 1b 02 00 00 00 00 00 00 03 00 00 00 00 00 00 00 0d 03 00 00 00 00 00 00 03 00 00 00 00 00 00 00 2f 02 00 00 00 00 00 00 03 00 00 00 00 00 00 00 a9 02 00 00 00 00 00 00 03 00 00 00 00 00 00 00 1b 03 00 00 00 00 00 00 03 00 00 00 00 00 00 00 bd 93 00 00 00 00 00 00 04 00 00 00 00 00 00 00 0d c8 05 00 00 00 00 00 04 00 00 00 00 00 00 00 17 34 08 00 00 00 00 00 04 00 00 00 00 00 00 00 63 fe 0b 00 00 00 00 00 04 00 00 00 00 00 00 00 f1 ce 0e 00 00 00 00 00 04 00 00 00 00 00 00 00 9f e6 0f 00 00 00 00 00 04 00 00 00 00 00 00 00 63 65 13 00 00 00 00 00 04 00 00 00 00 00 00 00 f5 db 17 00 00 00 00 00 04 00 00 00 00 00 00 00 0d ef 18 00 00 00 00 00 04 00 00 00 00 00 00 00 61 46 1d 00 00 00 00 00 04 00 00 00 00 00 00 00 71 10 1f 00 00 00 00 00 04 00 00 00 00 00 00 00 bb 00 23 00 00 00 00 00 04 00 00 00 00 00 00 00 f5 6b 26 00 00 00 00 00 04 00 00 00 00 00 00 00 f5 e4 28 00 00 00 00 00 04 00 00 00 00 00 00 00 53 2d 2c 00 00 00 00 00 04 00 00 00 00 00 00 00 71 4a 2e 00 00 00 00 00 04 00 00 00 00 00 00 00 c1 70 31 00 00 00 00 00 04 00 00 00 00 00 00 00 1b e7 34 00 00 00 00 00 04 00 00 00 00 00 00 00 29 99 39 00 00 00 00 00 04 00 00 00 00 00 00 00 55 a9 3b 00 00 00 00 00 04 00 00 00 00 00 00 00 bd 00 40 00 00 00 00 00 04 00 00 00 00 00 00 00 8f d3 00 00 00 00 00 00 5e 47 02 00 00 00 00 00 9f c1 13 00 00 00 00 00 18 3b 09 00 00 00 00 00 71 09 25 00 00 00 00 00 49 8b 18 00 00 00 00 00 29 5f 3f 00 00 00 00 00 b1 40 21 00 00 00 00 00 53 24 51 00 00 00 00 00 b6 57 22 00 00 00 00 00 8f 7d 59 00 00 00 00 00 21 c8 2c 00 00 00 00 00 71 d2 6d 00 00 00 00 00 c8 03 34 00 00 00 00 00 c1 58 82 00 00 00 00 00 de 93 42 00 00 00 00 00 f5 3c 8a 00 00 00 00 00 76 c1 4b 00 00 00 00 00 8f d7 a5 00 00 00 00 00 88 09 4d 00 00 00 00 00 f3 86 b2 00 00 00 00 00 33 c7 57 00 00 00 00 00 8f 80 c4 00 00 00 00 00 47 86 60 00 00 00 00 00 61 31 d4 00 00 00 00 00 c7 62 6a 00 00 00 00 00 c1 99 e3 00 00 00 00 00 63 82 75 00 00 00 00 00 c1 35 f5 00 00 00 00 00 04 e6 77 00 00 00 00 00 f5 ef 0b 01 00 00 00 00 c0 85 84 00 00 00 00 00 f3 80 16 01 00 00 00 00 67 d1 8e 00 00 00 00 00 29 43 27 01 00 00 00 00 2f 4d 96 00 00 00 00 00 89 fb 3d 01 00 00 00 00 89 b9 9e 00 00 00 00 00 f5 5a 4b 01 00 00 00 00 b6 fe a1 00 00 00 00 00 b9 e4 54 01 00 00 00 00 a9 71 ac 00 00 00 00 00"  
data = bytes(int(x,16) for x in raw.split())

base0 = struct.unpack('<q', bytes([0x3b,0xc8,0x0a,0x00,0x00,0x00,0x00,0x00]))[0]  
entries = [(base0, struct.unpack_from('<q', data, 0)[0])]  
for i in range(1, 84):  
off = (i-1)*16 + 8  
entries.append((struct.unpack_from('<q', data, off)[0], struct.unpack_from('<q', data, off+8)[0]))

def tower_mod256(b, exp):  
b = b & 0xff  
if b == 0: return 0  
if b == 1: return 1

val = b  
for _ in range(exp - 1):  
new_val = pow(b, val, 256)  
if new_val == val:  
break  
val = new_val  
return val

def char_of(base, exp):  
return (tower_mod256(base, exp) + 1) >> 1

print(''.join(chr(char_of(b, e)) for b, e in entries))  
```

#### Flag  
Running the script reconstructs all 84 characters of the flag in under a second, completely bypassing both the artificial delays and the expensive GMP computations:  
```bash  
$ python [solve.py](http://solve.py)  
RS{4_littl3_bi7_0f_numb3r_th30ry_n3v3r_hur7_4ny0n3_19b3369a25c78095689a38f81aa3f5e3}  
```

#### Notes  
The main trick here was recognizing that the program is computing power towers with GMP, which quickly becomes infeasible.

Once you notice everything is reduced mod 256, you can avoid huge numbers entirely and evaluate it efficiently using modular exponentiation.

For a full step-by-step breakdown and reversing details, I wrote a detailed post [here](<https://pnasis.gitlab.io/posts/ritsec-ctf-2026-reversing-writeups-part-2-not-quite-optimal/>) ;).
