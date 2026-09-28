---
title: "TLS - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "aes", "proof-of-work", "tls", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "We are given a python script chall.py and a remote service."
source:
  name: "CTFtime writeup #40591"
  url: "https://ctftime.org/writeup/40591"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "TLS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** TLS
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40591>

---
**Challenge Description**:  
We are given a python script `[chall.py](http://chall.py)` and a remote service. The service implements an RSA-based key exchange followed by AES encryption. It provides an Oracle that reveals information about the decrypted RSA value.

**Analysis**:  
The `[chall.py](http://chall.py)` script decrypts an incoming RSA ciphertext and checks if the decrypted value (the AES key) is greater than $2^{128}$.  
```python  
if key > 1<<128:  
raise Exception('Error in key decryption')  
```  
If this check passes, it proceeds to AES decryption. If the padding is invalid, it raises a `PaddingError`.  
This creates an **Oracle**:  
\- If the response is "something else went wrong", then $m' > 2^{128}$.  
\- If the response is "invalid padding" (or success), then $m' \le 2^{128}$.

The original AES key $m$ is generated as `bytes(8) + os.urandom(8)`, so $m < 2^{64}$.

**Solution**:  
We can perform a **Binary Search** for a multiplier $s$ such that $m \cdot s \approx 2^{128}$.  
We send ciphertexts corresponding to $c' = c \cdot s^e \pmod n$. These decrypt to $m' = m \cdot s \pmod n$.  
Since $m \cdot s$ is much smaller than $n$ (1337 bits), no modular wrapping occurs.

We search for the largest $s$ such that the Oracle returns True ($m \cdot s \le 2^{128}$).  
Once found, we can recover $m$:  
$$ m = \lfloor 2^{128} / s \rfloor $$

**Implementation**:  
1\. **Solver**:  
Connects to the server, extracts the RSA parameters, and performs binary search on $s$.  
[[solve_tls.py](http://solve_tls.py)](file:///home/mritunjya/ctf/2026/nullcon/crypto/TLS/[solve_tls.py](http://solve_tls.py))

2\. **Decryption**:  
Uses the recovered AES key $m$ to decrypt the flag.

**Snippet from Solver**:  
```python  
# Binary Search  
while low <= high:  
mid = (low + high) // 2  
c_prime = (c * pow(mid, e, n)) % n  
if oracle(c_prime): # checks if m*mid <= 2^128  
best_s = mid  
low = mid + 1  
else:  
high = mid - 1

m_rec = target_val // best_s  
```

**Flag**:  
`ENO{Y4y_a_f4ctor1ng_0rac13}`
