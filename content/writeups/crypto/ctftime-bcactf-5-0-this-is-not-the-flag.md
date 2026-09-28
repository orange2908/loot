---
title: "This is NOT the flag - BCACTF 5.0"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "base64", "bcactf", "bcactf-5-0", "ctf-writeup"]
summary: "We wrote a simple script that gave the flag."
source:
  name: "CTFtime writeup #39265"
  url: "https://ctftime.org/writeup/39265"
original_source: "https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/misc/This%20is%20NOT%20the%20flag"
ctf:
  name: "BCACTF 5.0"
  challenge: "This is NOT the flag"
---

## Metadata

- **CTF:** BCACTF 5.0
- **Task:** This is NOT the flag
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39265>
- **Original writeup:** <https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/misc/This%20is%20NOT%20the%20flag>

---
We wrote a simple script that gave the flag.  
```  
import base64

# string from the NOTflag.txt  
encoded_str = "nZyenIuZhMiXtoygzoygyJfMoJmTnsaC"  
decoded_bytes = base64.b64decode(encoded_str)

def xor_characters(s, key):  
return ''.join(chr(ord(char) ^ key) for char in s)

for key in range(256):  
xored = xor_characters(decoded_bytes.decode('latin1'), key)  
if "bcactf{" in xored:  
print(f"XOR {key}: {xored}")  
```

Flag: `bcactf{7hIs_1s_7h3_fla9}`
