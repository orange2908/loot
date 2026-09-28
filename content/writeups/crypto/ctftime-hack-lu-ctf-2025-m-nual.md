---
title: "MÄNUAL - Hack.lu CTF 2025"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "nual", "hack-lu-ctf", "hack-lu-ctf-2025", "2025", "ctf-writeup"]
summary: "The challenge presents us with an \"InstructionManual\" service that applies a series of transformations to 32-byte inputs."
source:
  name: "CTFtime writeup #40490"
  url: "https://ctftime.org/writeup/40490"
ctf:
  name: "Hack.lu CTF 2025"
  year: 2025
  challenge: "MÄNUAL"
---

## Metadata

- **CTF:** Hack.lu CTF 2025
- **Task:** MÄNUAL
- **Author team:** Cyclopropenylidene
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/40490>

---
# [Hack.lu](http://Hack.lu) CTF 2025 MÄNUAL Writeup (Crypto)

writeup: **fridgebuyer**

Category: **Crypto**

## Challenge Overview

The challenge presents us with an "InstructionManual" service that applies a series of transformations to 32-byte inputs. We can query the service up to 300 times with chosen inputs, and our goal is to recover the flag which has been encrypted using the same transformation process.

## Challenge Analysis

### The Server

The server ([server.py](http://server.py)) implements an `InstructionManual` class that:  
\- Operates on 32-byte (256-bit) values  
\- Applies a sequence of 46 operations (3 prefix + 40 random + 3 suffix)  
\- Each operation is one of three types:  
1\. **step_screw_in**: Bitwise rotation (left or right by a random amount)  
2\. **step_turn_around**: Endianness reversal (big ↔ little endian)  
3\. **step_hammer_together**: XOR with a random 256-bit value

### Key Vulnerability: Linearity over GF(2)

The critical insight is that ALL three operations are linear transformations over GF(2) (the field with two elements, 0 and 1):

1\. **Bitwise Rotation**: Permutes bits without changing their values  
\- Linear: rot(a ⊕ b) = rot(a) ⊕ rot(b)

2\. **Endianness Reversal**: Permutes bits in a fixed pattern  
\- Linear: rev(a ⊕ b) = rev(a) ⊕ rev(b)

3\. **XOR with constant**: Affine transformation  
\- Affine: (a ⊕ b) ⊕ k = (a ⊕ k) ⊕ (b ⊕ k) ⊕ k

Since composition of linear/affine transformations remains linear/affine, the entire build() function can be expressed as:

output = A × input + b (mod 2)

Where:  
\- A is a 256×256 binary matrix (the linear part)  
\- b is a 256-bit vector (the constant/affine part)  
\- All operations are in GF(2) (mod 2 arithmetic)

## Exploitation Strategy

### Step 1: Extract the Constant Vector b

Query the oracle with an all-zero input:  
\- Input: 0x00000...000 (32 bytes)  
\- Output: b

Since A × 0 = 0, the output is exactly b.

### Step 2: Extract the Matrix A

Query the oracle with 256 unit vectors (each having exactly one bit set):  
\- For bit position i: create input with only bit i = 1  
\- The output will be: A[:, i] + b (column i of A, plus b)  
\- Therefore: A[:, i] = output - b (mod 2)

After 256 queries, we have the complete 256×256 transformation matrix A.

### Step 3: Solve for the Flag

Once we have A and b, we can solve the linear system:

encrypted_flag = A × flag + b

Rearranging:  
flag = A^(-1) × (encrypted_flag - b)

We solve this using Gaussian elimination over GF(2).

## Solution Implementation

The [solve.py](http://solve.py) script implements this attack:

1\. **Query Phase** (257 queries total):  
\- 1 query for zero vector → extracts b  
\- 256 queries for unit vectors → extracts A

2\. **Solve Phase**:  
\- Receive encrypted flag  
\- Solve linear system using GF(2) Gaussian elimination  
\- Convert result back to ASCII

## Running the Exploit

```bash  
python3 [solve.py](http://solve.py) \--remote --host [manual.flu.xxx](http://manual.flu.xxx) \--port 1024  
```

### Exploit Output

```  
[+] Opening connection to [manual.flu.xxx](http://manual.flu.xxx) on port 1024: Done  
[*] Extracting linear system...  
[*] Querying zero vector to get constant b...  
[+] Got b: 4888c95bad64d6df1a1855aac0b0d83503f4785d235a39f2744190186bf61642  
[*] Querying unit vectors to build matrix A...  
[*] Progress: 0/256 columns...  
[*] Progress: 32/256 columns...  
[*] Progress: 64/256 columns...  
[*] Progress: 96/256 columns...  
[*] Progress: 128/256 columns...  
[*] Progress: 160/256 columns...  
[*] Progress: 192/256 columns...  
[*] Progress: 224/256 columns...  
[+] Extracted full 256×256 matrix A  
[*] Used 257 queries so far  
[*] Finishing queries to get encrypted flag...  
[+] Encrypted flag: 1511c582b6a84304d5400c241ba516b9dceda1073ac6e32ea81d8f567c6e8f8c  
[*] Solving linear system over GF(2)...

[+] FLAG: flag{crypt0_kn0wl3dg3_g4in3d_:3}  
```
