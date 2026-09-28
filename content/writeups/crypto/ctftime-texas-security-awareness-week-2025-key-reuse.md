---
title: "key-reuse - Texas Security Awareness Week 2025"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "key-reuse", "texas-security-awareness-week", "texas-security-awareness-week-2025", "2025", "ctf-writeup"]
summary: "writeup made by: romerquelle"
source:
  name: "CTFtime writeup #40163"
  url: "https://ctftime.org/writeup/40163"
ctf:
  name: "Texas Security Awareness Week 2025"
  year: 2025
  challenge: "key-reuse"
---

## Metadata

- **CTF:** Texas Security Awareness Week 2025
- **Task:** key-reuse
- **Author team:** kiberpsihoza.exe
- **CTFtime:** <https://ctftime.org/writeup/40163>

---
# key-reuse; Texas Security Awareness Week CTF 2025  
\---  
writeup made by: [romerquelle](<https://github.com/Romketha>)

category: crypto

## Task description:

I was pretty confident that nobody would be able to read my messages until I realized I used the same key twice! Flag format: texsaw{example_flag}

ciphertext.txt:

```  
200d1d2014071e152b1c1e022d2615100617112a0804

20000035191102062C1016091334110B1703182A020D  
```

## Solving the task:

The code below is a classic two-time pad known-plaintext attack (also called a "crib-dragging" attack):

```py  
def xor_bytes(b1, b2):  
return bytes([a ^ b for a, b in zip(b1, b2)])

ct1_hex = "200d1d2014071e152b1c1e022d2615100617112a0804"  
ct2_hex = "20000035191102062C1016091334110B1703182A020D"

ct1 = bytes.fromhex(ct1_hex)  
ct2 = bytes.fromhex(ct2_hex)

known_part_p1 = b"texsaw{"

xor_result = xor_bytes(ct1, ct2)

key_part = xor_bytes(known_part_p1, xor_result[:len(known_part_p1)])  
print("Recovered Key Part:", key_part)

key = key_part * (len(xor_result) // len(key_part)) + key_part[:len(xor_result) % len(key_part)]

p1 = xor_bytes(key, xor_result)  
p2 = key

print("P1:", p1.decode('utf-8', errors='ignore'))  
print("P2:", p2.decode('utf-8', errors='ignore'))  
```

Output:

```  
Recovered Key Part: b'theflag'  
P1: texsaw{going_upstream}  
P2: theflagtheflagtheflagt  
```

The flag is: `texsaw{going_upstream}`
