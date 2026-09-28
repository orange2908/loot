---
title: "Naptime - UIUCTF 2024"
category: "crypto"
type: "writeup"
tags: ["encryption", "crypto", "naptime", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "I just used to encryption to encrypt the alphabet, numbers and special characters and then binded each character to the ct array, giving us the flag."
source:
  name: "CTFtime writeup #39286"
  url: "https://ctftime.org/writeup/39286"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "Naptime"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** Naptime
- **Author team:** 1c3Gh3tt0
- **CTFtime tags:** encryption, crypto
- **CTFtime:** <https://ctftime.org/writeup/39286>

---
I just used to encryption to encrypt the alphabet, numbers and special characters and then binded each character to the ct array, giving us the flag.

```python  
flag = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890{}_!@#$%^&*()"

a = [66128, 61158, 36912, 65196, 15611, 45292, 84119, 65338]

temp = [273896, 179019, 273896, 247527, 208558, 227481,  
328334, 179019, 336714, 292819, 102108, 208558,  
336714, 312723, 158973, 208700, 208700, 163266,  
244215, 336714, 312723, 102108, 336714, 142107,  
336714, 167446, 251565, 227481, 296857, 336714,  
208558, 113681, 251565, 336714, 227481, 158973,  
147400, 292819, 289507]

bitstrings = []  
for c in flag:  
bitstrings.append(bin(ord(c))[2:].zfill(8))

ct = []

for bits in bitstrings:  
curr = 0  
for i, b in enumerate(bits):  
if b == "1":  
curr += a[i]  
ct.append(curr)

final = ""

for t in temp:  
ind = ct.index(t)  
final += flag[ind]

print(final)  
```

Flag: `uiuctf{i_g0t_sleepy_s0_I_13f7_th3_fl4g}`
