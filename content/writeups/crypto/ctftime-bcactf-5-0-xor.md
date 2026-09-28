---
title: "XOR - BCACTF 5.0"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "bcactf", "bcactf-5-0", "ctf-writeup"]
summary: "Wrote a script that XORs and gives the flag."
source:
  name: "CTFtime writeup #39268"
  url: "https://ctftime.org/writeup/39268"
original_source: "https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/rev/XOR"
ctf:
  name: "BCACTF 5.0"
  challenge: "XOR"
---

## Metadata

- **CTF:** BCACTF 5.0
- **Task:** XOR
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39268>
- **Original writeup:** <https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/rev/XOR>

---
Wrote a script that XORs and gives the flag.

```  
encrypted_flag = [  
0x21, 0x0F, 0x0A, 0x15, 0x3F, 0x29, 0x29, 0x6B, 0x13, 0x1C, 0x2C, 0x74,  
0x7D, 0x30, 0x5E, 0x50, 0x6E, 0x29, 0x2B, 0x24, 0x19, 0x0C, 0x67, 0x7D,  
0x05, 0x54, 0x7C, 0x34, 0x5C, 0x13, 0x32, 0x42, 0x29, 0x62, 0x7B, 0x0F,  
0x4E  
]

key = "ClkvKOR8JQA1JB731LeGkU7J4d2khDvrOPI63mM7"

flag = ""

for i in range(len(encrypted_flag)):  
decrypted_byte = encrypted_flag[i] ^ ord(key[i % len(key)])  
flag += chr(decrypted_byte)

print("Decrypted flag:", flag)  
```

Flag: `bcactf{SYMmE7ric_eNcrYP710N_4WD0f229}`
