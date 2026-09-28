---
title: "SYNDRÖM DECÖD - Hack.lu CTF 2025"
category: "crypto"
type: "writeup"
tags: ["crypto", "syndr", "dec", "hack-lu-ctf", "hack-lu-ctf-2025", "2025", "ctf-writeup"]
summary: "A McEliece cryptosystem challenge where the goal is to solve a syndrome decoding problem."
source:
  name: "CTFtime writeup #40491"
  url: "https://ctftime.org/writeup/40491"
ctf:
  name: "Hack.lu CTF 2025"
  year: 2025
  challenge: "SYNDRÖM DECÖD"
---

## Metadata

- **CTF:** Hack.lu CTF 2025
- **Task:** SYNDRÖM DECÖD
- **Author team:** Cyclopropenylidene
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/40491>

---
# [Hack.lu](http://Hack.lu) CTF 2025 SYNDRÖM DECÖD Writeup (Crypto)

writeup: **fridgebuyer**

Category: **Crypto**

## Challenge Overview  
A McEliece cryptosystem challenge where the goal is to solve a syndrome decoding problem.  
The service provides a syndrome and asks for an error vector of weight 4 that produces it.

## Vulnerability Analysis

### The Bug ([main.py:108](http://main.py:108))  
In the `ask_solution()` function, there is a critical logic error:

```python  
# Line 107: User's input is converted to a vector  
data = vector(GF(2), data)

# Line 108: BUG - uses 'e' instead of 'data'  
check_syndrome = encode(e, T, P)  
```

This should be:  
```python  
check_syndrome = encode(data, T, P)  
```

### Impact  
The syndrome verification always recomputes the syndrome from the original error `e`  
(randomly generated at startup) rather than from the user's submitted `data`.

This means:  
\- `syndrome` (line 75) = encode(e, T, P)  
\- `check_syndrome` (line 108) = encode(e, T, P) [SAME!]

The comparison on lines 114-117 will ALWAYS pass because both values are identical.

## Exploitation

### Strategy  
Submit ANY binary vector of length 3488 with exactly weight 4.  
The validation only checks:  
1\. Length is 3488  
2\. All bits are binary (0 or 1)  
3\. Hamming weight is 4

It never actually validates that the submitted vector produces the correct syndrome!

### Exploit Code  
```python  
# Create a binary vector of length 3488 with exactly 4 ones  
ERROR_LENGTH = 3488  
OMEGA = 4

error_vector = ['0'] * ERROR_LENGTH  
for i in range(OMEGA):  
error_vector[i] = '1'

solution = ''.join(error_vector)  
print(solution)  
```

### Execution  
```bash  
python3 [exploit.py](http://exploit.py) | openssl s_client -connect [4477016b56f0220d.syndroem.zone.re:443](http://4477016b56f0220d.syndroem.zone.re:443) -quiet 2>/dev/null  
```

## Root Cause  
Variable name confusion - using `e` (the secret error) instead of `data` (user input)  
in the syndrome computation, completely bypassing the cryptographic challenge.

## Flag  
flag{g0t_th3_ikEA_syNdroeM?_qLRII2UFkNsFg7lRNQ}
