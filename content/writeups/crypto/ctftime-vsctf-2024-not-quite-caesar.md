---
title: "not quite caesar - vsCTF 2024"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "cryptography", "caesar", "quite", "classical", "vsctf", "vsctf-2024", "2024", "ctf-writeup"]
summary: "lambda x: x // 3 if x % 3 == 0 else None, # x // 3 with an additional check"
source:
  name: "CTFtime writeup #39275"
  url: "https://ctftime.org/writeup/39275"
original_source: "https://medium.com/@zeroair41/decrypting-mystery-alexs-journey-through-the-not-quite-caesar-challenge-454a54eedc6a"
ctf:
  name: "vsCTF 2024"
  year: 2024
  challenge: "not quite caesar"
---

## Metadata

- **CTF:** vsCTF 2024
- **Task:** not quite caesar
- **Author team:** NCA@Nepal
- **CTFtime tags:** cryptography
- **CTFtime:** <https://ctftime.org/writeup/39275>
- **Original writeup:** <https://medium.com/@zeroair41/decrypting-mystery-alexs-journey-through-the-not-quite-caesar-challenge-454a54eedc6a>

---
```  
import random

# Set the seed to match the original script  
random.seed(1337)

# Define the original operations  
ops = [  
lambda x: x + 3,  
lambda x: x - 3,  
lambda x: x * 3,  
lambda x: x ^ 3,  
]

# Define the reverse operations  
reverse_ops = [  
lambda x: x - 3,  
lambda x: x + 3,  
lambda x: x // 3 if x % 3 == 0 else None, # x // 3 with an additional check  
lambda x: x ^ 3,  
]

# The 'out' list from the challenge  
out = [354, 112, 297, 119, 306, 369, 111, 108, 333, 110, 112, 92, 111, 315, 104, 102, 285, 102, 303, 100, 112, 94, 111, 285, 97, 351, 113, 98, 108, 118, 109, 119, 98, 94, 51, 56, 159, 50, 53, 153, 100, 144, 98, 51, 53, 303, 99, 52, 49, 128]

# List to store the recovered flag bytes  
flag = []

# Iterate over the output and reverse the applied operations  
for v in out:  
op_index = random.randint(0, 3) # Get the index of the operation applied  
reverse_op = reverse_ops[op_index] # Get the corresponding reverse operation  
reversed_value = reverse_op(v) # Apply the reverse operation

# Check if reverse operation was valid  
if reversed_value is not None:  
flag.append(reversed_value)  
else:  
print(f"Failed to reverse operation for value {v} with operation index {op_index}")  
flag.append(ord('?')) # Use '?' for unknown characters

# Convert the flag list back to bytes and decode, replacing invalid bytes with '?'  
flag_bytes = bytes(flag)  
print(flag_bytes.decode('utf-8', 'replace'))  
```
