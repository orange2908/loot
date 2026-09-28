---
title: "MTH211 (h4ckc0n 2025 CTF) - h4ckc0n 2025"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "proof-of-work", "mth211", "h4ckc0n", "h4ckc0n-2025", "2025", "ctf-writeup"]
summary: "A tidy write-up + reference solver for a challenge where the private key is K = oldk · g and oldk = p1 · p2 with 28-bit primes."
source:
  name: "CTFtime writeup #40447"
  url: "https://ctftime.org/writeup/40447"
original_source: "https://github.com/salahbgf288/CTFs/tree/main/MTH211%20(h4ckc0n%202025%20CTF)"
ctf:
  name: "h4ckc0n 2025"
  year: 2025
  challenge: "MTH211 (h4ckc0n 2025 CTF)"
---

## Metadata

- **CTF:** h4ckc0n 2025
- **Task:** MTH211 (h4ckc0n 2025 CTF)
- **Author team:** WhiteDukesDZ
- **CTFtime:** <https://ctftime.org/writeup/40447>
- **Original writeup:** <https://github.com/salahbgf288/CTFs/tree/main/MTH211%20(h4ckc0n%202025%20CTF)>

---
# ? MTH211 (h4ckc0n 2025 CTF) 

<div align="center">

![Made with Python]([https://img.shields.io/badge/Made%20with-Python-3776AB?logo=python&logoColor=white](https://img.shields.io/badge/Made%20with-Python-3776AB?logo=python&logoColor=white))  
![CTF Crypto](<https://img.shields.io/badge/Category-Crypto-purple>)  
![Prime Search](<https://img.shields.io/badge/Search-28--bit%20primes-0A84FF>)  
![Status](<https://img.shields.io/badge/Status-Solved-34C759>)  
![PRs welcome](<https://img.shields.io/badge/PRs-welcome-21C55D?logo=github>)

**A tidy write-up + reference solver for a challenge where the private key is `K = old_k · g` and `old_k = p1 · p2` with 28-bit primes.**   
</div>

\---

## ? Table of Contents  
\- [✨ Overview](#-overview)  
\- [? Challenge Setup](#-challenge-setup)  
\- [? Approach](#-approach)  
\- [? Results](#-results)  
\- [▶️ Quickstart](#️-quickstart)  
\- [? Reference `[solve.py](http://solve.py)`](#-reference-solvepy)  
\- [⚙️ Performance Tips](#️-performance-tips)  
\- [? Repository Structure](#-repository-structure)  
\- [? Acknowledgements](#-acknowledgements)

\---

## ✨ Overview  
The core idea revolves around computing the private exponent **`K`**:  
\- We have `new_k = K = old_k · g`.  
\- The challenge “gift” gives us a fast way to validate candidates for `K`.  
\- We exploit the structure **`old_k = p1 · p2`** where `p1`, `p2` are **28-bit primes**.   
There are **exactly 7,027,290 primes** in `[2^27, 2^28 − 1]`, making search feasible.

> [!TIP]  
> Once `old_k` is identified, compute `K = old_k · g`, verify with the **gift** relation, and decrypt.

\---

## ? Challenge Setup  
You’re given:  
\- `n` (RSA-like modulus),  
\- `g` (multiplier),  
\- `gift` (verification value),  
\- `cipher` (ciphertext as integer).

Hidden structure guaranteed by the challenge:  
\- `old_k = p1 · p2` with 28-bit primes `p1`, `p2`,  
\- `K = old_k · g` is the **private exponent**.

\---

## ? Approach

### High-Level Flow  
```mermaid  
flowchart TD  
A[Start] --> B[Generate 28-bit primes]  
B --> C[Search/derive old_k = p1·p2]  
C --> D[Compute K = old_k · g]  
D --> E{Verify: pow(K, 13, n) == gift?}  
E -- yes --> F[Decrypt: m = pow(cipher, K, n)]  
E -- no --> B  
F --> G[Parse bytes → UTF-8]  
G --> H[Done]  
```

### Key Moves  
\- ? **Prime space**: iterate/enumerate 28-bit primes efficiently (segmented sieve or fast primality).  
\- ? **Candidate testing**: use the **gift** check to quickly validate the derived `K`.  
\- ⚡ **Decrypt**: once verified, compute `m = pow(cipher, K, n)` and decode.

> [!NOTE]  
> The gift check used here is `pow(K, 13, n) == gift`. Replace `13` with whatever the challenge specifies if different.

\---

## ? Results

**Recovered factors & key**  
\- `p1 = 233679967`   
\- `p2 = 171077047`   
\- `K = 39977278697417449`

**Verification**  
```text  
pow(K, 13, n) == gift → OK ✅  
```

**Decryption**  
```text  
m = pow(cipher, K, n)  
→ plaintext bytes: b'd4rkc0de{att3nding_cl4ss3s_paid_off}'  
→ plaintext (utf-8): d4rkc0de{att3nding_cl4ss3s_paid_off}  
```

> ? **Flag**: `d4rkc0de{att3nding_cl4ss3s_paid_off}`  
\---

## ? Reference `[solve.py](http://solve.py)`  
> Replace the placeholders for `n`, `g`, `gift`, and `cipher` with the real challenge values.

```python  
# [solve.py](http://solve.py)

# === Challenge constants (fill these) ===  
n = ... # RSA-like modulus (int)  
g = ... # multiplier for old_k (int)  
gift = ... # verification value (int)  
cipher = ... # ciphertext as int

# === Recovered values from the search ===  
p1 = 233679967  
p2 = 171077047

old_k = p1 * p2  
K = old_k * g

# Verify against the 'gift' relation  
assert pow(K, 13, n) == gift, "Verification failed: wrong K or constants."

# Decrypt  
m_int = pow(cipher, K, n)  
m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")  
try:  
print("Recovered plaintext:", m_bytes.decode("utf-8"))  
except UnicodeDecodeError:  
print("Recovered plaintext bytes:", m_bytes)  
```

\---

## ⚙️ Performance Tips

\- ? **Prime generation**: Use a **segmented sieve** to enumerate all 28-bit primes quickly; cache to disk for reuse.  
\- ? **Vectorized checks**: Batch modular operations when possible; Python’s built-in `pow(base, exp, mod)` is highly optimized.  
\- ? **Parallelism**: Multiprocess prime work; shard the search space by ranges or by hashing primes to workers.  
\- ? **Caching**: Persist candidate sets and intermediate checks to skip repeated work during iterations.

\---
