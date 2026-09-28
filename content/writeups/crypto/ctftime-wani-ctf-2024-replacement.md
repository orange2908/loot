---
title: "replacement - Wani CTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "replacement", "wani-ctf", "wani-ctf-2024", "2024", "ctf-writeup"]
summary: "Wrote a script that gave us the flag."
source:
  name: "CTFtime writeup #39241"
  url: "https://ctftime.org/writeup/39241"
ctf:
  name: "Wani CTF 2024"
  year: 2024
  challenge: "replacement"
---

## Metadata

- **CTF:** Wani CTF 2024
- **Task:** replacement
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39241>

---
Wrote a script that gave us the flag.

```  
import hashlib

# Given encoded list  
enc = [ ] # the txt list

# Step 1: Convert each integer back to its hexadecimal string representation  
hex_strings = [hex(val)[2:] for val in enc]

# Step 2: Determine the original ASCII values from their MD5 hashes  
decoded_characters = []  
for hex_string in hex_strings:  
found = False  
for ascii_value in range(256): # Possible ASCII values range from 0 to 255  
md5_hash = hashlib.md5(str(ascii_value).encode()).hexdigest()  
if md5_hash == hex_string:  
decoded_characters.append(chr(ascii_value))  
found = True  
break  
if not found:  
print(f"No match found for hash: {hex_string}")

# Join the decoded characters to form the original string  
original_string = ''.join(decoded_characters)

print("Original string:", original_string)  
```

Flag: `FLAG{13epl4cem3nt}`
