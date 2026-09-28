---
title: "Delicious Looking Problem - 0xFUN CTF 2026"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "gcd", "ecb", "discrete-log", "chinese-remainder", "proof-of-work", "0xfun-ctf", "0xfun-ctf-2026", "2026", "ctf-writeup"]
summary: "Delicious Looking Problem | 0xFun CTF 2026"
source:
  name: "CTFtime writeup #40675"
  url: "https://ctftime.org/writeup/40675"
original_source: "https://axl0t0l.github.io/posts/0xFun/DeliciousLookingProblem"
ctf:
  name: "0xFUN CTF 2026"
  year: 2026
  challenge: "Delicious Looking Problem"
---

## Metadata

- **CTF:** 0xFUN CTF 2026
- **Task:** Delicious Looking Problem
- **Author team:** 0xDr460nZ
- **CTFtime:** <https://ctftime.org/writeup/40675>
- **Original writeup:** <https://axl0t0l.github.io/posts/0xFun/DeliciousLookingProblem>

---
Delicious Looking Problem | 0xFun CTF 2026 __

Contents __

Delicious Looking Problem | 0xFun CTF 2026

__

[![](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)

##  Overview __

  * **Platform:** [0xFun](https://ctf.0xfun.org/)
  * **Challenge:** [Delicious Looking Problem](https://ctf.0xfun.org/challenges#Delicious%20Looking%20Problem-165)
  * **Categories:** Crypto
  * **Rating:** /10
  * **Difficulty:** Medium
  * **Sovling Time:** ~30 Minutes


## Challenge __

> “ _A delicious looking problem for starters. Always remember that the answer to life, universe and everything is 42._

> _Have fun:3_ ”

## Walkthrough __

### Recon __

If we look into the provided code we can see that it uses only 42 bit long primes (2^42) which is pretty small for AES and can be Bruteforced pretty quick….

####  The Code __

____

`

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
```

| 

```
     from Crypto.Util.number import *
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from random import getrandbits
    import hashlib
    import os
    
    flag = b'redacted'
    key = os.urandom(len(flag)) 
    Max_sample = 67 # :3
    
    def get_safe_prime(bits):
        while True:
            q = getPrime(bits-1)
            p = 2*q + 1
            if isPrime(p):
                return p, q
    
    def primitive_root(p, q):
        while True:
            g = getRandomRange(3, p-1)
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g 
        
    def gen():
        p, q = get_safe_prime(42)   # Should've chosen a bigger prime, but got biased:3 [https://www.youtube.com/watch?v=aboZctrHfK8]
        g = primitive_root(p, q)
        h = pow(g, bytes_to_long(key), p)
    
        return g, h, p
    
    Max_samples = Max_sample//8 # Can't give you that many samples:3
    with open('output.txt', 'w') as f:
        for i in range(Max_samples):
            g, h, p = gen()
            f.write(f'sample #{i+1}:\n')
            f.write(f'{g = }\n')
            f.write(f'{h = }\n')
            f.write(f'{p = }\n')
    
        cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag, 16)).hex()
        f.write(f'{ct = }')
```  
  
---|---  
`

### Solution Approach __

> “ _Flag format:`0xfun{}`_”

This challenge is a classic case of a “Broken Math Lock.” While the encryption used is AES-256 (which is super strong), the secret password used to generate the AES key is hidden behind some very weak math, _Yes weaker than Van der Waals force bond_.

#### The Math Lock (DLP)__

The script uses the Discrete Logarithm Problem (DLP). In high level crypto, this is a one-way street, it’s easy to calculate \\(g^{x} (mod\ \rho)\\) but nearly impossible to go backward and find .However, the security of this “lock” depends entirely on the size of the prime number \\(\rho\\) .Standard Primes: 2048 bits (unhackable). This Challenge: 42 bits. Because 42 bits is so small (roughly 13 digits), a modern computer doesn’t even break a sweat. It can “brute force” the math or use smart algorithms like Baby-step Giant-step (BSGS) to find the secret exponent \\(x\\) in less than a second.

####  Piecing the Puzzle (CRT)__

The secret key used in the script is about 43 bytes long (~344 bits), which is way bigger than our 42-bit prime. This is why we have 8 samples. Each sample gives us a tiny piece of the secret. We can use the Chinese Remainder Theorem (CRT) to stitch those 8 pieces together. It’s like having 8 different “clocks” all running at different speeds; by looking at where the hands are on all of them, we can calculate the exact time the master clock started.

####  The Final Step __

Even after using CRT, we might be off by a tiny bit because the key could be slightly larger than our combined math result. We run a small loop to check the last few possibilities:

  * Take the candidate key.
  * Hash it with SHA-256 to get the actual AES key.
  * Try to decrypt the AES-ECB ciphertext.
  * If the output looks like a flag (starts with 0xFun{}), we’ve won!


#### Solving Code __

____

`

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
    46
    47
    48
    49
    50
    51
    52
    53
    54
    55
    56
    57
    58
    59
    60
    61
    62
    63
    64
    65
    66
    67
    68
    69
    70
    71
    72
    73
    74
    75
    76
    77
    78
    79
    80
    81
    82
    83
    84
    85
    86
    87
    88
    89
    90
    91
    92
    93
    94
    95
    96
    97
    98
    99
    100
    101
    102
    103
    104
    105
    106
    107
```

| 

```
     from sympy.ntheory import discrete_log
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from math import gcd, lcm
    from functools import reduce
    import hashlib
    
    # ── Data ──────────────────────────────────────────────────────────────────────
    samples = [
        dict(g=227293414901,  h=1559214942312, p=3513364021163),
        dict(g=2108076514529, h=1231299005176, p=2627609083643),
        dict(g=1752240335858, h=1138499826278, p=2917520243087),
        dict(g=1564551923739, h=283918762399,  p=2602533803279),
        dict(g=1809320390770, h=700655135118,  p=2431482961679),
        dict(g=1662077312271, h=354214090383,  p=2820691962743),
        dict(g=474213905602,  h=1149389382916, p=3525049671887),
        dict(g=2013522313912, h=2559608094485, p=2679851241659),
    ]
    ct = bytes.fromhex(
        '175a6f682303e313e7cae01f4579702ae6885644d46c15747c39b85e5a1fab66'
        '7d2be070d383268d23a6387a4b3ec791'
    )
    
    # ── Step 1: Solve DLP in each small group ────────────────────────────────────
    # p is 42-bit safe prime (p = 2q+1, q 41-bit prime)
    # g is a primitive root → order = p-1 = 2q
    # DLP gives key_int ≡ x_i  (mod p_i - 1)
    print("[*] Solving discrete logs (42-bit primes, trivial BSGS)...")
    residues, moduli = [], []
    for i, s in enumerate(samples):
        g, h, p = s['g'], s['h'], s['p']
        x = discrete_log(p, h, g)
        assert pow(g, x, p) == h, "DLP sanity check failed"
        print(f"  sample #{i+1}: key_int ≡ {x}  (mod {p-1})")
        residues.append(x)
        moduli.append(p - 1)
    
    # ── Step 2: Generalised CRT (moduli share factor 2) ──────────────────────────
    def extended_gcd(a, b):
        if b == 0: return a, 1, 0
        g2, x2, y2 = extended_gcd(b, a % b)
        return g2, y2, x2 - (a // b) * y2
    
    def modinv(a, mod):
        _, x, _ = extended_gcd(a % mod, mod)
        return x % mod
    
    def generalised_crt(residues, moduli):
        x, m = residues[0], moduli[0]
        for r, n in zip(residues[1:], moduli[1:]):
            g = gcd(m, n)
            assert (r - x) % g == 0, "Inconsistent system"
            inv = modinv(m // g, n // g)
            x = x + m * (((r - x) // g) * inv % (n // g))
            m = m * n // g
            x %= m
        return x, m
    
    print("\n[*] Running generalised CRT...")
    key_val, combined_mod = generalised_crt(residues, moduli)
    assert combined_mod == reduce(lcm, moduli), "CRT modulus ≠ LCM sanity check"
    print(f"  key_int ≡ key_val  (mod combined_mod)")
    print(f"  key_val   = {key_val}  ({key_val.bit_length()} bits)")
    print(f"  combined_mod bits = {combined_mod.bit_length()}")
    
    # ── Step 3: AES helpers ──────────────────────────────────────────────────────
    def aes_ecb_decrypt(key32, ct):
        cipher = Cipher(algorithms.AES(key32), modes.ECB())
        dec = cipher.decryptor()
        return dec.update(ct) + dec.finalize()
    
    def unpad_pkcs7(data):
        pad_len = data[-1]
        if pad_len == 0 or pad_len > 16:
            raise ValueError("bad padding")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("bad padding")
        return data[:-pad_len]
    
    # ── Step 4: Brute-force over residue class ───────────────────────────────────
    # AES-ECB ciphertext = 48 bytes  →  flag = 33..47 bytes (PKCS7)
    # key_val is 324 bits; minimum key_len to hold it = 41 bytes.
    # For key_len = 43: ~1 million candidates, trivially feasible.
    print("\n[*] Searching residue class for correct key (key_len=43, ~1M candidates)...")
    key_len = 43
    max_val = 1 << (key_len * 8)
    c = key_val
    cnt = 0
    flag = None
    
    while c < max_val:
        kb = c.to_bytes(key_len, 'big')
        digest = hashlib.sha256(kb).digest()
        raw = aes_ecb_decrypt(digest, ct)
        try:
            pt = unpad_pkcs7(raw)
            if all(32 <= b < 127 for b in pt):
                flag = pt.decode()
                print(f"\n[+] FLAG: {flag}")
                break
        except Exception:
            pass
        c += combined_mod
        cnt += 1
    
    if flag is None:
        print("Not found in key_len=43, try expanding the search.")
    print(f"\n[*] Checked {cnt:,} candidates.")
```  
  
---|---  
`

And there we got the flag! [![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Delicious-Looking-Problem/flag.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Delicious-Looking-Problem/flag.png)

#### Flag __

`0xfun{pls_d0nt_hur7_my_b4by(DLP)_AI_kun!:3}`

**_Hope you enjoined the writeup, Don’t forget to leave a comment or a star on the[github repo](https://github.com/Axl0t0l) (;_**

__[0xFun CTF 2026](https://axl0t0l.github.io/categories/0xfun-ctf-2026/), [WarmUp](https://axl0t0l.github.io/categories/warmup/)

__[Crypto](https://axl0t0l.github.io/tags/crypto/)

This post is licensed under [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) by the author.

Share [ __](https://twitter.com/intent/tweet?text=Delicious%20Looking%20Problem%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xFun%2FDeliciousLookingProblem "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Delicious%20Looking%20Problem%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&u=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xFun%2FDeliciousLookingProblem "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xFun%2FDeliciousLookingProblem&text=Delicious%20Looking%20Problem%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l "Telegram") __
