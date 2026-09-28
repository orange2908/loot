---
title: "Faultline - CTF@CIT 2026"
category: "rev"
subcategory: "symbolic-execution"
type: "writeup"
tags: ["rev", "xor", "z3", "objdump", "faultline", "symbolic-execution", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Category: Reverse Engineering"
source:
  name: "CTFtime writeup #40748"
  url: "https://ctftime.org/writeup/40748"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Faultline"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Faultline
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40748>

---
# Writeup: Faultline

\- Category: Reverse Engineering  
\- Value: 856 pts (145 solves)  
\- Author: ronnie  
\- Status: **SOLVED**

## Challenge

We are given an ELF 64-bit statically linked executable named `faultline`. Running it reveals a "seam optimizer" command-line tool with several subcommands: `notes`, `score`, `trace`, `token`, `compare`, `nudge`, and `submit`.

The goal is to find a 12-character profile (from the alphabet `BCDFGHJKLMNPQRST`) that achieves a "historical lock score" of exactly 2026, generate its token, and submit it to get the flag.

## Solution

The `notes` command provides hints about the scoring mechanism:

\- Profiles are scored through three harmonic families: `stress`, `shear`, and `grain`.  
\- `stress` uses adjacent symbols on a 2:3 wheel.  
\- `shear` couples symbols two positions apart through XOR.  
\- `grain` folds positions `i`, `i+1`, and `i+3`.  
\- `load` and `seal` also matter.

By using the `trace` command on simple inputs like `BBBBBBBBBBBB`, `CBBBBBBBBBBB`, `DBBBBBBBBBBB`, etc., we can reverse-engineer the exact formulas for each metric. Let $x_i$ be the index of the $i$-th character in the alphabet (0 to 15):

1\. **Stress**: $S_i = (2x_i + 3x_{i+1}) \pmod{16}$  
2\. **Shear**: $H_i = x_i \oplus x_{i+2}$  
3\. **Grain**: $G_i = (x_i - x_{i+1} + x_{i+3}) \pmod{16}$  
4\. **Load**: $L = \sum_{i=0}^{11} x_i$  
5\. **Seal**: $E = \sum_{i=0}^{11} ((i+5) \pmod{16}) \cdot x_i \pmod{16}$

By dumping the target arrays from the binary using `objdump`, we find the exact target values for each metric:

\- Target Stress: `[2, 5, 11, 10, 5, 1, 13, 4, 3, 3, 14]`  
\- Target Shear: `[5, 5, 15, 8, 5, 6, 7, 4, 5, 5]`  
\- Target Grain: `[3, 11, 3, 4, 14, 4, 5, 6, 1]`  
\- Target Load: `93`  
\- Target Seal: `9`

Since the maximum possible score (2026) is only achieved when all metrics perfectly match their targets, this is a constraint satisfaction problem. We can use the Z3 theorem prover to find the solution:

```python  
import z3

x_bv = [z3.BitVec(f'x_bv_{i}', 4) for i in range(12)]  
s_bv = z3.Solver()

stress_target = [2, 5, 11, 10, 5, 1, 13, 4, 3, 3, 14]  
for i in range(11):  
s_bv.add((2 * x_bv[i] + 3 * x_bv[i+1]) == stress_target[i])

shear_target = [5, 5, 15, 8, 5, 6, 7, 4, 5, 5]  
for i in range(10):  
s_bv.add((x_bv[i] ^ x_bv[i+2]) == shear_target[i])

grain_target = [3, 11, 3, 4, 14, 4, 5, 6, 1]  
for i in range(9):  
s_bv.add((x_bv[i] - x_bv[i+1] + x_bv[i+3]) == grain_target[i])

sum_x = z3.ZeroExt(4, x_bv[0])  
for i in range(1, 12):  
sum_x += z3.ZeroExt(4, x_bv[i])  
s_bv.add(sum_x == 93)

seal_target = 9  
seal_sum = z3.ZeroExt(4, x_bv[0]) * 5  
for i in range(1, 12):  
seal_sum += z3.ZeroExt(4, x_bv[i]) * ((i + 5) % 16)  
s_bv.add((seal_sum & 15) == seal_target)

if s_bv.check() == z3.sat:  
m = s_bv.model()  
res = [m[x_bv[i]].as_long() for i in range(12)]  
alphabet = 'BCDFGHJKLMNPQRST'  
profile = ''.join(alphabet[v] for v in res)  
print('FOUND:', profile)  
```

Running this script yields the profile: `SDPKGTCMJRFL`.

We then generate the token for this profile:

```bash  
./faultline token SDPKGTCMJRFL  
# Output: Z2L-2F5-BUBP  
```

And finally, submit the profile and token to get the flag:

```bash  
./faultline submit SDPKGTCMJRFL Z2L-2F5-BUBP  
# Output: CIT{12z4PXVTa3x3}  
```

## Flag

```text  
CIT{12z4PXVTa3x3}  
```
