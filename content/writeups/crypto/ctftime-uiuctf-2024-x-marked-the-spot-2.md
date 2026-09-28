---
title: "X Marked the Spot - UIUCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "marked", "spot", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "After checking the given files we made a script that gave the flag."
source:
  name: "CTFtime writeup #39287"
  url: "https://ctftime.org/writeup/39287"
original_source: "https://github.com/juke-33/Write-ups/tree/main/UIUCTF%202024/Cryptography/X%20Marked%20the%20Spot"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "X Marked the Spot"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** X Marked the Spot
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39287>
- **Original writeup:** <https://github.com/juke-33/Write-ups/tree/main/UIUCTF%202024/Cryptography/X%20Marked%20the%20Spot>

---
After checking the given files we made a script that gave the flag.  
```python  
from itertools import cycle

# Given ciphertext file  
ciphertext_file = "ct"

# Read the ciphertext  
with open(ciphertext_file, "rb") as f:  
ct = f.read()

# We know the flag starts with "uiuctf{"  
known_plaintext = b"uiuctf{"

# XOR the first 7 bytes of ciphertext with the known plaintext to get the key  
partial_key = bytes(ct_byte ^ pt_byte for ct_byte, pt_byte in zip(ct[:7], known_plaintext))

# The key is 8 bytes long, we can deduce the 8th byte by XORing the 8th byte of the ciphertext with the 8th character of the flag  
# Here we assume the 8th character of the flag is the first character after '{' which could be any valid character, we will brute-force it  
for i in range(256):  
potential_key = partial_key + bytes([i])  
decrypted_flag = bytes(ct_byte ^ key_byte for ct_byte, key_byte in zip(ct, cycle(potential_key)))  
if decrypted_flag.startswith(b"uiuctf{") and decrypted_flag.endswith(b"}"):  
print(decrypted_flag.decode())  
break  
```

Flag: `uiuctf{n0t_ju5t_th3_st4rt_but_4l50_th3_3nd!!!!!}`
