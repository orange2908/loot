---
title: "scrambled - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "scrambled", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We were given a main.py that encrypted the flag in two steps:"
source:
  name: "CTFtime writeup #39957"
  url: "https://ctftime.org/writeup/39957"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "scrambled"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** scrambled
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39957>

---
# rev/Scrambled

We were given a [main.py](http://main.py) that encrypted the flag in two steps:  
1\. Each character of the flag is XORed with a single-byte key.  
2\. The encrypted data is split into chunks of 4 bytes which are then shuffled using a random seed (0-10) and then converted to hex before giving as output.

The given output was:   
```bash  
1e78197567121966196e757e1f69781e1e1f7e736d6d1f75196e75191b646e196f6465510b0b0b57  
```

So in order to reverse the encryption we could write a simple brute script that brutes both the seed and the XOR key to find the correct flag.

```python  
import random

def decode_flag(scrambled_result, key, seed):  
chunk_size = 4  
chunks = [scrambled_result[i:i+chunk_size] for i in range(0, len(scrambled_result), chunk_size)]  
  
random.seed(seed)  
shuffled_indices = list(range(len(chunks)))  
random.shuffle(shuffled_indices)  
  
unshuffled_chunks = [None] * len(chunks)  
for i, chunk in enumerate(chunks):  
unshuffled_chunks[shuffled_indices[i]] = chunk  
  
xor_result = [item for chunk in unshuffled_chunks for item in chunk]  
  
flag = "".join([chr(c ^ key) for c in xor_result])  
return flag

def main():  
scrambled_hex = "1e78197567121966196e757e1f69781e1e1f7e736d6d1f75196e75191b646e196f6465510b0b0b57"  
  
scrambled_result = [int(scrambled_hex[i:i+2], 16) for i in range(0, len(scrambled_hex), 2)]  
  
for seed in range(11):  
for key in range(256):  
flag = decode_flag(scrambled_result, key, seed)  
if all(32 <= ord(c) <= 126 for c in flag):  
print(f"Seed: {seed}, Key: {key}, Flag: {flag}")

if __name__ == "__main__":  
main()  
```

On running this we can brute and hence, reverse the encryption to get our flag.

```bash  
ENO{5CR4M83L3D_3GG5_4R3_1ND33D_T45TY!!!}  
```
