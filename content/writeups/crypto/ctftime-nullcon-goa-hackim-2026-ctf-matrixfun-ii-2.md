---
title: "Matrixfun II - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "sage", "base64", "matrixfun", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "We are given a python script chall.py and a remote service."
source:
  name: "CTFtime writeup #40592"
  url: "https://ctftime.org/writeup/40592"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Matrixfun II"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Matrixfun II
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40592>

---
**Challenge Description**:  
We are given a python script `[chall.py](http://chall.py)` and a remote service. The service encrypts messages using a matrix-based key.

**Analysis**:  
The encryption logic in `[chall.py](http://chall.py)` reveals it is an Affine Hill Cipher over a custom alphabet of size 65.  
```python  
cipher[i:i+n] = A @ block + b  
return cipher % MOD  
```  
The key consists of a $16 \times 16$ matrix $A$ and a vector $b$ with entries in $\mathbb{Z}_{65}$. The input message is Base64 encoded before encryption, which is why the modulus is 65 (Base64 alphabet size + 1 for padding).

**Solution**:  
The encryption is an affine transformation:  
$$ C = A \cdot V + b \pmod{65} $$

We can recover the key $(A, b)$ using a **Chosen Plaintext Attack (CPA)**.  
1\. **Recover $b$**:  
Send an all-zero vector $V_0 = [0, 0, \dots, 0]$.  
$$ C_0 = A \cdot V_0 + b = b $$  
Thus, $b = C_0$.  
The index 0 typically corresponds to 'a' in the custom alphabet depending on implementation, or we can just verify which character maps to 0.

2\. **Recover $A$**:  
To recover the $i$-th column of $A$, send a vector $V_i$ which has a 1 at position $i$ and 0 elsewhere (basis vector $e_i$).  
$$ C_i = A \cdot e_i + b = Col_i(A) + b $$  
$$ Col_i(A) = C_i - b $$  
Repeating this for all 16 columns recovers the entire matrix $A$.

3\. **Decrypt Flag**:  
Once we have $A$ and $b$, we can decrypt the provided flag cipher $C_{flag}$:  
$$ V_{flag} = A^{-1} \cdot (C_{flag} - b) \pmod{65} $$  
The challenge uses $\mathbb{Z}_{65}$, which is not a field but a ring ($\mathbb{Z}_{5} \times \mathbb{Z}_{13}$). However, as long as $\det(A)$ is coprime to 65, the matrix implies an inverse.

**Implementation**:

1\. **Solver**:  
We wrote a Python script to interact with the server and perform the CPA.  
[[solve_matrix.py](http://solve_matrix.py)](file:///home/mritunjya/ctf/2026/nullcon/crypto/matrix_fun_2/[solve_matrix.py](http://solve_matrix.py))

2\. **Decryption**:  
We used SageMath to invert the matrix modulo 65 and decrypt the flag ciphertext.  
[[solve_matrix_sage.py](http://solve_matrix_sage.py)](file:///home/mritunjya/ctf/2026/nullcon/crypto/matrix_fun_2/[solve_matrix_sage.py](http://solve_matrix_sage.py))

**Snippet from Solver**:  
```python  
# Recover b  
c0 = get_cipher(s, basis_0_bytes)  
b_vec = c0 % MOD

# Recover A  
for i in range(n):  
# ... create basis vector ei ...  
ci = get_cipher(s, vec_bytes)  
col = (ci - b_vec) % MOD  
A_cols.append(col)  
```

**Flag**:  
`ENO{l1ne4r_alg3br4_i5_ev3rywh3re}`
