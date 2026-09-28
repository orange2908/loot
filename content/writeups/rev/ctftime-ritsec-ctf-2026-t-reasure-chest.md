---
title: "T-reasure Chest - RITSEC CTF 2026"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "xtea", "reversing", "ghidra", "t-reasure", "chest", "static-analysis", "ritsec-ctf", "ritsec-ctf-2026", "2026", "ctf-writeup"]
summary: "We’re given a stripped 64-bit ELF that asks for a “magic word”."
source:
  name: "CTFtime writeup #40702"
  url: "https://ctftime.org/writeup/40702"
original_source: "https://ctftime.org/team/431287"
ctf:
  name: "RITSEC CTF 2026"
  year: 2026
  challenge: "T-reasure Chest"
---

## Metadata

- **CTF:** RITSEC CTF 2026
- **Task:** T-reasure Chest
- **Author team:** Echelon Obscura
- **CTFtime tags:** xtea, reversing
- **CTFtime:** <https://ctftime.org/writeup/40702>
- **Original writeup:** <https://ctftime.org/team/431287>

---
### T-reasure Chest (Reversing) - RITSEC CTF 2026  
We’re given a stripped 64-bit ELF that asks for a “magic word”. No symbols, so straight into Ghidra.

#### Approach

Looking at `main`, the program:  
1\. Reads user input  
1\. Pads it to 8-byte blocks  
1\. Runs it through a function (which I named `tiny_encrypt`)  
1\. Compares the result with a hardcoded buffer (`memcmp`)

Instead of guessing the input, the goal is to understand the transformation and reverse it!

Inside `tiny_encrypt`, the structure immediately stood out, especially the constant `-0x61c88647` (which is the two’s complement representation of `0x9E3779B9`, a well-known constant in cryptography). That’s a big hint that this is `XTEA`.

Since it’s a symmetric cipher, it’s much easier to just decrypt the embedded ciphertext using the same key found in the binary.

#### Solution Script  
```python  
#!/usr/bin/env python3  
import struct

ctx = bytes([  
0x38,0x75,0x5b,0xcb, 0x44,0xd2,0xbe,0x5d,  
0x96,0x9c,0x56,0x43, 0xea,0x98,0x06,0x75,  
0x4a,0x48,0x13,0xe6, 0xd4,0xe8,0x8e,0x4f,  
0x72,0x70,0x8b,0xff, 0xdc,0x99,0xf8,0x76,  
0xc5,0xc9,  
])

key = struct.unpack('<4I', b'tiny_encrypt_key')

def u32(x): return x & 0xFFFFFFFF

def xtea_decrypt(v0, v1):  
delta = 0x9E3779B9  
s = u32(delta * 32)  
for _ in range(32):  
v1 = u32(v1 - ((u32(v0*16)+key[2]) ^ u32(s+v0) ^ (u32(v0>>5)+key[3])))  
v0 = u32(v0 - ((u32(v1*16)+key[0]) ^ u32(s+v1) ^ (u32(v1>>5)+key[1])))  
s = u32(s - delta)  
return v0, v1

out = bytearray()  
for i in range(len(ctx) // 8):  
v0, v1 = struct.unpack_from('<2I', ctx, i*8)  
d0, d1 = xtea_decrypt(v0, v1)  
out += struct.pack('<2I', d0, d1)

print(out[:33].rstrip(b'\x00').decode())  
```

#### Flag  
Running the script processes the ciphertext block by block, applies the inverse XTEA rounds and reconstructs the original plaintext. After stripping padding bytes, the recovered string is printed, which corresponds directly to the flag for the challenge:  
```bash  
$ python [solve.py](http://solve.py)  
RS{oh_its_a_TEAreasure_chest}  
```

#### Notes  
The main trick here was recognizing XTEA from the constants and structure. Once that clicks, the challenge becomes straightforward.

For a full step-by-step breakdown and reversing details, I wrote a detailed post [here](<https://pnasis.gitlab.io/posts/ritsec-ctf-2026-reversing-writeups-part-1-t-reasure-chest/>) ;).
