---
title: "Mersenne Mayhem - L3akCTF 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "gcd", "sage", "cbc", "hidden-number-problem", "off-by-one", "l3akctf", "l3akctf-2025", "2025", "ctf-writeup"]
summary: "Challenge: Mersenne Mayhem"
source:
  name: "CTFtime writeup #40344"
  url: "https://ctftime.org/writeup/40344"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-07-14-Mersenne-Mayhem-writeup"
ctf:
  name: "L3akCTF 2025"
  year: 2025
  challenge: "Mersenne Mayhem"
---

## Metadata

- **CTF:** L3akCTF 2025
- **Task:** Mersenne Mayhem
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/40344>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-07-14-Mersenne-Mayhem-writeup>

---
## Mersenne Mayhem - L3AK-CTF 2025 Write-up

![Banner](https://writeups.thebusfactoris1.online/assets/files/meresene/image.png)

**Challenge:** Mersenne Mayhem   
**Category:** Cryptography   
**Points:** 198

### Introduction

Alright, let's break down "Mersenne Mayhem." The challenge drops two files on us: [`[chal.py](http://chal.py)`](https://writeups.thebusfactoris1.online/assets/files/meresene/[chal.py](http://chal.py)) and [`output.txt`](https://writeups.thebusfactoris1.online/assets/files/meresene/output.txt). A quick peek at [`output.txt`](https://writeups.thebusfactoris1.online/assets/files/meresene/output.txt) reveals a massive prime `p`, another huge number `h`, a ciphertext, and some parameters. The prime `p` looks suspiciously like a Mersenne prime, which is a good hint.

The real juice is in `[chal.py](http://chal.py)`. We see the core of the crypto system is this equation:  
`h ≡ inverse(g, p) * f (mod p)`

A little bit of algebra transforms this into a much friendlier form:  
`h * g ≡ f (mod p)`

This means that for some integer `k`, `h*g - k*p = f`. Here's the kicker: the script also tells us that `f` and `g` are generated to be "small" numbers with a very low Hamming weight (only 10 bits set to '1'). This is a classic "Hidden Number Problem." Since `f` is tiny compared to `p`, the term `h*g` must be extremely close to a multiple of `p`. This implies that `h/p` is an excellent rational approximation of `k/g`.

And how do we find the best rational approximations of a number? With the **Continued Fractions Algorithm**, which is basically what the Extended Euclidean Algorithm (EEA) does under the hood. The plan was set: use the EEA on `h` and `p` to find candidates for `f` and `g`, check them against the constraints (bit length and Hamming weight), and then decrypt the flag. Simple, right? Well...

### The Journey of Trial and Error

**Attempt #1: The Naive Python Script**

My first instinct was to whip up a quick Python script. I copied the massive numbers from `output.txt`, implemented the EEA, and ran it.

*Crash.*

```  
AttributeError: 'sage.rings.integer.Integer' object has no attribute 'bit_length'  
```

Ah. It seems I copied the numbers from a Sage-generated output, and my local Python didn't know what to do with Sage's integer types. But the error was a blessing in disguise. It screamed, "USE SAGEMATH, YOU GOOF!" The challenge was clearly designed for the Sage environment.

**Attempt #2: Migrating to SageMath (and Failing Again)**

Okay, time to play in the right sandbox. I fired up a Sage shell. The first fix was easy: Sage integers use `.nbits()` instead of `.bit_length()` and `.popcount()` instead of `.bit_count()`. I made the changes, feeling pretty smart. I ran the script.

```  
Failed to find f and g.  
```

My disappointment was immeasurable and my day was ruined. What went wrong? I stepped through my EEA implementation. It turned out I had a subtle but critical logic bug. I was comparing the remainder from one step of the algorithm with a coefficient from the *next* step. They have to be from the same iteration to satisfy the `h*g ≡ f (mod p)` relation. A classic off-by-one-in-a-loop headache.

**Attempt #3: The Final Countdown... Almost**

I refactored the loop to correctly pair the candidates at each step. This had to be it. I ran the script again.

```  
Found a potential match!  
f = 1200148...  
g = 2931004...  
Traceback (most recent call last):  
...  
AttributeError: 'sage.rings.integer.Integer' object has no attribute 'to_bytes'  
```

Success! And... another crash. We found `f` and `g`, but the celebration was cut short. The problem was that `f` and `g` were still Sage integer objects. The decryption part of the script uses PyCryptodome, which expects standard Python `int`s and `bytes`. Sage objects and standard Python libraries don't always play nice.

The fix was beautifully simple: just cast the secret back to a Python `int` before trying to convert it to bytes.

`py_secret = int(secret)`

With that final change, the script ran flawlessly.

### The Final Solution

This is the final SageMath script that incorporates all the fixes from our little adventure. It correctly uses Sage methods, has the proper EEA logic, and handles the type conversion needed for decryption.

```python  
from sage.all_cmdline import * # import sage library  
_sage_const_2814112013697373133393152975842584191818662.....  
import math  
from hashlib import sha3_256  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import unpad

ciphertext_hex = "41b53384d92de5c678a2138a0da552d174d77c420591b29ccb7c7610310bf82bcb58f903a423d7d257e3ee4ae2c4da69"  
p = _sage_const_28141120136973731333.... # p from output.txt  
h = _sage_const_1420555256339029007623997... # h from output.txt  
xi1 = _sage_const_0p31   
xi2 = _sage_const_0p69   
w = _sage_const_10 

n = _sage_const_11213   
bf = int(n * xi1) # 3476  
bg = int(n * xi2) # 7736

def solve():  
r_prev, s_prev = p, _sage_const_0   
r_curr, s_curr = h, _sage_const_1 

while r_curr != _sage_const_0 :  
f_cand = abs(r_curr)  
g_cand = abs(s_curr)

if f_cand.nbits() <= bf and g_cand.nbits() <= bg:  
if f_cand.popcount() == w and g_cand.popcount() == w:  
if gcd(f_cand, g_cand) == _sage_const_1 :  
print("Found a potential match!")  
print(f"f = {f_cand}")  
print(f"g = {g_cand}")  
return f_cand, g_cand  
quotient = r_prev // r_curr  
r_prev, r_curr = r_curr, r_prev - quotient * r_curr  
s_prev, s_curr = s_curr, s_prev - quotient * s_curr  
  
return None, None

f, g = solve()

if f and g:  
secret = (f * g) % p

py_secret = int(secret)

secret_bytes = py_secret.to_bytes((py_secret.bit_length() + _sage_const_7 ) // _sage_const_8 , byteorder='big')  
key = sha3_256(secret_bytes).digest()

ciphertext_raw = bytes.fromhex(ciphertext_hex)  
iv = ciphertext_raw[:_sage_const_16 ]  
encrypted_flag = ciphertext_raw[_sage_const_16 :]

cipher = AES.new(key, AES.MODE_CBC, iv)  
decrypted_padded_flag = cipher.decrypt(encrypted_flag)  
flag = unpad(decrypted_padded_flag, AES.block_size)  
  
print(f"{flag.decode()}")  
else:  
print("❌")  
```

```bash  
python3 [mersenne.py](http://mersenne.py)  
Found a potential match!  
f=120014834986216379489585938321164138443107863953955843155510106935559.....   
g = 29310043358604083666325266523559047353216814526488322966431306597511531073... L3ak{4jp2_n0t_s0_str0ng}  
```  
### FLAG  
```bash  
Flag: L3ak{4jp2_n0t_s0_str0ng}  
```
