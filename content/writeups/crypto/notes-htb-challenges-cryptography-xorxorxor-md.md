---
title: "Xorxorxor (Cryptography)"
category: "crypto"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "xorxorxor", "cryptography", "crypto", "htb-challenges"]
summary: "Personal note: Xorxorxor (Cryptography)."
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Cryptography/xorxorxor.md"
---

```python
flag = b'HTB{'
enc = bytes.fromhex("134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9")

key = b''
for k in range(4):
    key += bytes([enc[k] ^ flag[k]])
print("[+] Key : ",key)

result = b''
for k in range(len(enc)):
    result += bytes([enc[k] ^ key[k % len(key)]])
print("[+] Flag is : ",result)

\#HTB{rep34t3d_x0r_n0t_s0_s3cur3}
```

---

*From your own notes: `HTB Challenges/Cryptography/xorxorxor.md`*
