---
title: "Speak Friend, and Enter - DownUnderCTF 2025"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "cryptography-rsa", "cryptography", "rsa", "aes", "ecb", "cbc", "xor", "proof-of-work", "meet-in-the-middle", "cbc-mac", "downunderctf", "downunderctf-2025", "2025", "ctf-writeup"]
summary: "Challenge: Speak Friend, and Enter"
source:
  name: "CTFtime writeup #40354"
  url: "https://ctftime.org/writeup/40354"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-07-24-Speak-Friend-and-Enter-writeup"
ctf:
  name: "DownUnderCTF 2025"
  year: 2025
  challenge: "Speak Friend, and Enter"
---

## Metadata

- **CTF:** DownUnderCTF 2025
- **Task:** Speak Friend, and Enter
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** crypto, cryptography-rsa, cryptography
- **CTFtime:** <https://ctftime.org/writeup/40354>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-07-24-Speak-Friend-and-Enter-writeup>

---
## Speak Friend, and Enter - DUCTF 2025 Write-up

![Banner](https://writeups.thebusfactoris1.online/assets/files/speak/image.png)

**Challenge:** `Speak Friend, and Enter`  
**Category:** `Cryptography`  
**Points:** `195`  
**Author:** `LTFZP`  
**Team:** [`The Bus Factor is 1:`](<https://ctftime.org/team/389946>)

### Introduction

This challenge was a fantastic journey through the world of RSA and message authentication codes. It started with a simple-looking signature request and quickly spiraled into a series of "Aha!" moments and deceptive rabbit holes. The server greets us, gives us a random string, and asks us to sign it. The catch? We have to provide a public key that passes a very specific integrity check. Let's dive into how we went from being completely stuck to snatching the flag.

### Reconnaissance: Understanding the Gates

First things first, we were given the [`[server.py](http://server.py)`](https://writeups.thebusfactoris1.online/assets/files/speak/[server.py](http://server.py)) source code. This is always a gift in crypto challenges. Let's break down what it does:

1\. It generates a random `challenge_string`.  
2\. It expects us to send a JSON object: `{"public_key": (int), "signature": (int)}`.  
3\. It performs two critical checks on our submitted `public_key`:  
* **The CMAC Check:** It calculates a CMAC (Cipher-based Message Authentication Code) using AES on our public key and compares it to a hardcoded value: `9d4dfd...`. This is the main gate we need to get through.  
* **The Bit Length Check:** It ensures our `public_key.bit_length()` is exactly `2048`. No more, no less.  
4\. If our key passes both checks, it verifies our RSA signature against the `challenge_string`.

The most interesting line was `cc = CMAC.new(NIST_SP_800_38B_Appendix_D1_K, ciphermod=AES)`. That variable name is a massive clue.

### Trial & Error: The Walls We Hit

#### Attempt #1: The Brute-Force Fantasy

My first, most naive thought was, "What if I just generate 2048-bit RSA keys in a loop until one of them happens to produce the correct CMAC?" I wrote a quick script to do this and... it got stuck. Of course, it did. The output of the CMAC is 128 bits long. The odds of a randomly generated key producing the exact target hash are 1 in 2^128. We'd be waiting until the heat death of the universe. This was a dead end.

#### Attempt #2: The Collision Course

The variable `NIST_SP_800_38B_Appendix_D1_K` screamed "standard test vector!" A quick search confirmed that the NIST standard for CMAC uses a well-known public key for its examples: `0x2b7e...`. Now that we knew the secret key for the CMAC, we could do more than just guess.

The next logical step was a collision attack. Since CMAC-AES works in blocks, maybe we could take a valid 2048-bit number, convert it to bytes, and just append a few more bytes to it until the CMAC matched the target. This is a common technique.

**The Problem:** This approach slammed right into the `public_key.bit_length() != 2048` check. Appending even a single byte to a 2048-bit number would make its bit length greater than 2048, causing the server to reject it immediately. Another dead end. This felt like the server was specifically designed to prevent the most obvious attacks.

### The Real Vulnerability: A Prime Suspect

After hitting those walls, I took a step back and re-read the server code one more time. It checks the CMAC of the public key. It checks the bit length. It uses the public key as the modulus `n` in the RSA signature verification. But what does it *not* check?

**It never checks if the public key is a composite number.**

This was the critical oversight. Standard RSA relies on the modulus `n` being a product of two large primes, `p` and `q`, because the difficulty of factoring `n` is what makes it secure. But the mathematical formula for RSA verification, `pow(signature, e, n)`, works just fine if `n` is a prime number!

If we use a prime number `p` as our modulus, calculating the private key becomes trivial:  
\- `phi(p)` is simply `p - 1`.  
\- The private exponent `d` is `pow(e, -1, p - 1)`.

The challenge was now transformed. We didn't need to find a composite number `n=p*q`. We just needed to find a **2048-bit prime number** that satisfied the server's CMAC check.

This is still a hard problem, but it's solvable with a meet-in-the-middle approach:  
1\. Generate a random 240-byte (1920-bit) prefix for our number.  
2\. Using our knowledge of the CMAC key, perform the CBC-MAC calculation on this prefix.  
3\. From the result, we can work backward from the `TARGET_MAC` to calculate exactly what the final 16-byte block needs to be to produce the correct signature.  
4\. Combine our prefix and the calculated final block to form a 2048-bit candidate number.  
5\. Check if this candidate is prime using a Miller-Rabin test (`isPrime`).  
6\. Repeat until we find one! This search is much, much faster than brute force.

### The Final Solution

This led to the final script. It implements the logic above: construct a number that is guaranteed to have the right CMAC, then check if it's prime. Once a prime candidate is found, it calculates the private key, signs the challenge, and sends it off.

```python  
#!/usr/bin/env python3

import json  
import os  
from binascii import unhexlify

from Crypto.Cipher import AES  
from Crypto.Hash import SHA512  
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime  
from pwn import remote

NIST_KEY = unhexlify('2b7e151628aed2a6abf7158809cf4f3c')  
TARGET_MAC = unhexlify('9d4dfd27cb483aa0cf623e43ff3d3432')  
E = 65537  
BLOCK_SIZE = 16

def xor_bytes(a, b):  
return bytes(x ^ y for x, y in zip(a, b))

def construct_public_key_candidate(prefix_bytes):  
assert len(prefix_bytes) == 240, "240 bytes"  
  
cipher = AES.new(NIST_KEY, AES.MODE_ECB)  
  
intermediate_state = b'\x00' * BLOCK_SIZE  
for i in range(0, len(prefix_bytes), BLOCK_SIZE):  
block = prefix_bytes[i:i+BLOCK_SIZE]  
intermediate_state = cipher.encrypt(xor_bytes(block, intermediate_state))  
  
c15 = intermediate_state  
  
decrypted_target = cipher.decrypt(TARGET_MAC)  
last_block_xor_c15 = decrypted_target  
last_block = xor_bytes(last_block_xor_c15, c15)  
  
full_candidate_bytes = prefix_bytes + last_block  
return bytes_to_long(full_candidate_bytes)

io = remote("[chal.2025.ductf.net](http://chal.2025.ductf.net)", 30008)  
challenge_line = io.recvline().decode()  
print(challenge_line.strip())  
challenge_string = challenge_line.split(': ')[1].strip().encode()

s = bytes_to_long(SHA512.new(challenge_string).digest())

print("Searching for a prime public key that matches the CMAC...")

while True:  
# Generate a random 240-byte prefix.  
# Set the most significant bit to 1 to ensure the final number is 2048 bits.  
prefix = b'\x80' + os.urandom(239)  
  
# Construct the full number that will have the correct CMAC  
n = construct_public_key_candidate(prefix)  
  
# Check if our candidate is prime  
if isPrime(n):  
p_key = n  
print(f"Found a prime public key: {str(p_key)[:20]}...")  
break

# We found a prime p_key, so calculating the private key is easy  
phi = p_key - 1  
d = pow(E, -1, phi)

signature = pow(s, d, p_key)

payload = json.dumps({"public_key": p_key, "signature": signature})

print("Submitting")  
io.sendlineafter(b'json string {"public_key": (int), "signature" : (int)}:\n', payload.encode())

response = io.recvall().decode()  
print(response)  
io.close()  
```

And running this script gives us the sweet, sweet flag. This challenge was a perfect example of how understanding the fine details of a cryptographic protocol, and looking for what *isn't* there, can lead to a solution.

```bash  
python3 [solved.py](http://solved.py)  
[+] Opening connection to [chal.2025.ductf.net](http://chal.2025.ductf.net) on port 30008: Done  
Here is your challenge string: 422tVuQt6VQon1mZAvNZn1v4BaApDGwFPHvrEYJZ7AHSMCj9  
Searching for a prime public key that matches the CMAC...  
Found a prime public key: 1624138363415910882128084935450711517963936342433932445997999493762979467836777328158099146071953213870570376748471761241065  
5031928821701555152275962447479666827159143705819781611522470789948831140761990401416405830832514105269643874840568089127072469236978841233220280795797283859446379727145961408738920880005482778850109083336389014682039692592648321314236252333251755975943176745178134048755313999680106549998455366607238790685627233618679565155857605693102860822733856542111974190387238818370861266149656868273427732216539794927295185656276392810980482492148536024205683453369948440985529206457015662707235907771 Submitting  
[+] Receiving all data: Done (64B)  
[*] Closed connection to [chal.2025.ductf.net](http://chal.2025.ductf.net) port 30008  
Signature verified! Here is your flag: DUCTF{Z3n_th3_fl@g_Out!}  
```

### FLAG  
```bash  
FLAG : DUCTF{Z3n_th3_fl@g_Out!}  
```
