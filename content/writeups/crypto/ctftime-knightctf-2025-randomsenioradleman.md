---
title: "RandomseniorAdleman - KnightCTF 2025"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "2025", "knightctf", "adleman", "kingctf", "xor", "rsa", "prng", "proof-of-work", "knightctf-2025", "ctf-writeup"]
summary: "Leonard Adleman (born December 31, 1945) is an American computer scientist."
source:
  name: "CTFtime writeup #39824"
  url: "https://ctftime.org/writeup/39824"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "RandomseniorAdleman"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** RandomseniorAdleman
- **Author team:** Nc{Cat}
- **CTFtime tags:** 2025, knightctf, adleman, kingctf, xor, rsa, ctf
- **CTFtime:** <https://ctftime.org/writeup/39824>

---
# Writeup: Knightctf 2025 / RandomseniorAdleman  
### - For those who have an itch in the back of their brain:  
**Leonard Adleman** (born December 31, 1945) is an American computer scientist. He is one of the creators of the [RSA (cryptosystem)](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>) encryption algorithm, for which he received the 2002 [Turing Award](<https://en.wikipedia.org/wiki/Turing_Award>).<ref name=":0">{{Cite web|title = Leonard M. Adleman {{!}} American computer scientist|url = <http://www.britannica.com/biography/Leonard-M-Adleman>|website = Encyclopædia Britannica|access-date = 2015-11-24}}</ref> He is also known for the creation of the field of [DNA computing](<https://en.wikipedia.org/wiki/DNA_computing>) and coining the term [computer virus](<https://en.wikipedia.org/wiki/Computer_virus>).<ref>{{Cite web |title=Professor Len Adleman explains how he coined the term “computer virus” |url=<https://www.welivesecurity.com/2017/11/01/professor-len-adleman-explains-computer-virus-term/> |access-date=2024-12-26 |website=[www.welivesecurity.com](http://www.welivesecurity.com) |language=en}}</ref>

Source: Wikipedia  
url: do some Search, you lazy person

## General view:  
In this challenge, we are given an RSA cryptosystem with a custom method for generating the prime \\( p \\). The goal is to decrypt the ciphertext \\( c \\) to recover the plaintext. Here's a detailed walkthrough of the solution:

\---

## **Given Information**  
\- **\\( q \\)**: A known 256-bit prime number.  
\- **\\( e \\)**: The public exponent.  
\- **\\( c \\)**: The ciphertext to decrypt.  
\- **Hint**: Three phrases are provided:  
1\. `"usedistofindouttheseed"`  
2\. `"thisisthekeytogetyourseed"`  
3\. `"anothersecrethere"`

The hint suggests that these phrases are used to derive a seed through an "Axe-Ore" swirl (likely XOR) and a hashing operation. This seed is then used to generate the prime \\( p \\).

\---

## **Step 1: Understanding the Seed Generation**  
The hint mentions performing an "Axe-Ore" swirl among the three phrases. This is likely a reference to the XOR operation, which is commonly used in cryptography for combining data. Here's how the seed is derived:

1\. **Encode the Phrases**: Convert the three phrases into byte arrays.  
```python  
bytes1 = phrase1.encode()  
bytes2 = phrase2.encode()  
bytes3 = phrase3.encode()  
```

2\. **Perform XOR Operation**: XOR the three byte arrays together. This ensures that the result is a combination of all three phrases.  
```python  
xor_result = bytes(x ^ y ^ z for x, y, z in zip(bytes1, bytes2, bytes3))  
```

3\. **Hash the Result**: Use SHA-256 to hash the XOR result. This produces a 256-bit value, which is suitable for seeding a random number generator.  
```python  
hash_object = hashlib.sha256(xor_result)  
seed = int.from_bytes(hash_object.digest(), 'big')  
```

4\. **Seed the Random Number Generator**: Use the derived seed to initialize Python's `random` module.  
```python  
random.seed(seed)  
```

\---

## **Step 2: Generating the Prime \\( p \\)**  
With the random number generator seeded, we can generate a candidate for \\( p \\):  
1\. Generate a random 256-bit integer.  
```python  
p_candidate = random.getrandbits(256)  
```

2\. Find the next prime number after the candidate to ensure \\( p \\) is prime.  
```python  
p = nextprime(p_candidate)  
```

\---

## **Step 3: Computing the RSA Parameters**  
Now that we have both \\( p \\) and \\( q \\), we can compute the RSA parameters:  
1\. Compute the modulus \\( n \\):  
```python  
n = p * q  
```

2\. Compute Euler's totient function \\( \phi(n) \\):  
```python  
phi(n) = (p - 1) * (q - 1)  
```

3\. Compute the private key \\( d \\) as the modular inverse of \\( e \\) modulo \\( \phi(n) \\):  
```python  
d = mod_inverse(e, phi_n)  
```

\---

## **Step 4: Decrypting the Ciphertext**  
With the private key \\( d \\), we can decrypt the ciphertext \\( c \\):  
1\. Compute the plaintext \\( m \\) using modular exponentiation:  
```python  
m = pow(c, d, n)  
```

2\. Convert the plaintext integer \\( m \\) into bytes:  
```python  
plaintext_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')  
```

3\. Attempt to decode the bytes into a string. If decoding fails (e.g., if the plaintext is not valid UTF-8), print the raw bytes.  
```python  
try:  
plaintext = plaintext_bytes.decode()  
print("Decrypted plaintext:", plaintext)  
except UnicodeDecodeError:  
print("Decrypted message (as bytes):", plaintext_bytes)  
```

\---

\---

## **Full Code**  
```python  
from sympy import nextprime, mod_inverse  
import hashlib  
import random

q = 81950208731605030173072901497240676460946134422613059941413476068465656250011  
e = 15537  
c = 4744275480125761149475439652189568532719997985297643024045625900665305682630452044004013647350658428069718952801828651333880186841289630294789054322237585

phrase1 = "usedistofindouttheseed"  
phrase2 = "thisisthekeytogetyourseed"  
phrase3 = "anothersecrethere"

bytes1 = phrase1.encode()  
bytes2 = phrase2.encode()  
bytes3 = phrase3.encode()

xor_result = bytes(x ^ y ^ z for x, y, z in zip(bytes1, bytes2, bytes3))

hash_object = hashlib.sha256(xor_result)  
seed = int.from_bytes(hash_object.digest(), 'big')

random.seed(seed)

p_candidate = random.getrandbits(256)  
p = nextprime(p_candidate)

n = p * q

phi_n = (p - 1) * (q - 1)

d = mod_inverse(e, phi_n)

m = pow(c, d, n)

plaintext_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')

try:  
plaintext = plaintext_bytes.decode()  
print("Decrypted plaintext:", plaintext)  
except UnicodeDecodeError:  
print("Decrypted message (as bytes):", plaintext_bytes)

```

. ##Good Luck

\---
