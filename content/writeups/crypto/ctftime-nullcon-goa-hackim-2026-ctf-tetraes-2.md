---
title: "Tetraes - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "tetraes", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge provides a custom AES implementation (chall.py) with 16 rounds."
source:
  name: "CTFtime writeup #40589"
  url: "https://ctftime.org/writeup/40589"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Tetraes"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Tetraes
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40589>

---
### Challenge Analysis  
The challenge provides a custom AES implementation (`[chall.py](http://chall.py)`) with 16 rounds. Key features:  
\- **Linear Key Schedule**: The round keys are just cyclic rotations of the master key.  
\- **Modified S-box**: The S-box is mostly identical to AES, but `S[0]` is modified to `0x64`.  
\- **Encryption Service**: The server allows encrypting chosen plaintexts. It also provides `encrypt(key, key)` at the start.

### Vulnerability: S-box Collision  
Analysis of the modified S-box revealed that `S[0] = 0x64`. However, `0x64` is *also* the output for another input value (`140` or `0x8C`).  
Thus, we have a collision: `S[0] == S[140]`.

### Attack Strategy  
Since the collision happens in the Substitution layer of the very first round, we can exploit it using a Chosen Plaintext Attack.  
1\. The input to the first S-box is `State = P ^ K ^ const` (where `const` accounts for `ark(0)`).  
2\. If we find two plaintexts `P1` and `P2` such that `P1 ^ P2 = 140` (difference of `0x8C`) and they produce the *same* ciphertext, it implies their internal states collided after the first S-box application.  
3\. This collision only happens if the input bytes to the S-box were `{0, 140}` (in some order).  
4\. Therefore, `P1[i] ^ K[i] ^ const` must be either `0` or `140`.  
5\. This reduces the key search space for each byte to just 2 candidates.

### Solution  
We implemented a pipelined attack script (`[solve_tetra_pipeline.py](http://solve_tetra_pipeline.py)`) that:  
1\. Connects to the server.  
2\. For each byte index `i`, sends a batch of 256 chosen plaintexts (varying byte `i`) to find the collision pair.  
3\. Recovers 2 candidates for each key byte.  
4\. Locally verifies the $2^{16}$ possible keys against the provided `encrypt(key, key)` ciphertext.  
5\. Submits the correct key to retrieve the flag.

### Results  
**Recovered Key**: `146d789803e6b937cfd4d627d3b159f6`  
**Collision Pairs (Example)**:  
\- Byte 0: `62` and `178` (colliding S-box inputs `0` and `140`)  
\- Byte 1: `109` and `225`  
\- Byte 2: `120` and `244`

### Flag  
`ENO{a1l_cop5_ar3_br0adca5t1ng_w1th_t3tra}`
