---
title: "odd-bacon - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "odd-bacon", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The method to solve this is pretty straightforward (provided by Warri and implemented by Maximxls):"
source:
  name: "CTFtime writeup #40038"
  url: "https://ctftime.org/writeup/40038"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "odd-bacon"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** odd-bacon
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40038>

---
The method to solve this is pretty straightforward (provided by Warri and implemented by Maximxls):

\- implement the speckcipher operation in c/cpp using external library or otherwise  
\- ncat server, get encrypted flag, and encrypted 00000000, 00000001. Maybe get more such data points  
\- xor encrypted parts to eliminate k2 netting us F(k1^m0) ^ F(k1^m1) with known m0, m1  
\- in c/cpp, brute all 2*32 possible k1 values (i assume python is too slow for us rn)

once we recover the right k1 we can recover the right k2 letting us decrypt the encrypted flag

```  
from pwn import *  
from speck import SpeckCipher

cipher = SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32)

pi = remote("52.59.124.14", 5033)

enc = bytes.fromhex(pi.recvline().decode())

pi.sendlineafter("> ", "00000000")  
enc0 = pi.recvline().decode()  
print(enc0)  
pi.sendlineafter("> ", "00000001")  
print(pi.recvline().decode())

k1 = int(input("> "), 16)

k2 = (int(enc0, 16) ^ cipher.encrypt(k1)).to_bytes(4, byteorder = 'big')  
k1 = k1.to_bytes(4, byteorder = 'big')

def F(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).decrypt(int.from_bytes(block, byteorder = 'big')).to_bytes(4, byteorder = 'big')

flag = b''.join(xor(k1, F(xor(enc[4*i:4*i+4], k2))) for i in range(len(enc) // 4))

print(flag)  
```

This prints the results for 00000000 and 00000001  
We input the key, one sample is enough when we search exhaustively.
