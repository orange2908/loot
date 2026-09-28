---
title: "Pasty - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "cbc", "xor", "pasty", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "A pastebin service named \"Pasty\" allows users to create and view text pastes."
source:
  name: "CTFtime writeup #40581"
  url: "https://ctftime.org/writeup/40581"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Pasty"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Pasty
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40581>

---
**Challenge Description**:  
A pastebin service named "Pasty" allows users to create and view text pastes. Each paste is protected by a signature (`sig`) derived from its ID. The objective is to retrieve the paste with the ID `flag`.

**Analysis**:  
The application uses a custom HMAC-like signature scheme implemented in `sig.php` to verify pastes. The signature generation involves:  
1\. Hashing the input ID (`$d`) using SHA-256.  
2\. Taking the first 24 bytes of the hash of the secret key (`$k`) as the Key Material.  
3\. Splitting this Key Material into 3 equal blocks (8 bytes each).  
4\. Iterating 4 times to produce a 32-byte signature. In each iteration, a "key block" is selected from the Key Material based on the current byte of the ID hash (`ord($h[$s]) % 3`).  
5\. The selected key block is XORed with the ID hash block and the previous output block (CBC-like chaining).

$$ O_i = B_i \oplus K_{p_i} \oplus O_{i-1} $$

**Vulnerability**:  
The key selection logic depends entirely on the input ID, which we control when creating a new paste. Since the signature (`sig`) is returned to us, and the ID (`$d`) is known, we can reverse the XOR operations to recover the chosen key block ($K_{p_i}$).  
$$ K_{p_i} = O_i \oplus B_i \oplus O_{i-1} $$  
By creating multiple pastes with random IDs, we can collect enough equations to recover all 3 unique key blocks (indexed 0, 1, 2) that constitute the entire Key Material.

**Solution**:  
1\. We wrote a script `[solve.py](http://solve.py)` that repeatedly creates pastes to harvest signatures.  
2\. For each paste, it reverses the signature generation to recover parts of the secret key hash.  
3\. Once all 3 unique key blocks are recovered, the script locally computes the valid signature for the target ID `flag`.  
4\. Submitting a request with `id=flag` and the forged signature retrieves the flag.

**Solver**: `web/pasty/[solve.py](http://solve.py)`

**Flag**: `ENO{cr3at1v3_cr7pt0_c0nstruct5_cr4sh_c4rd5}`
