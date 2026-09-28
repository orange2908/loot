---
title: "Iced TEA - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
type: "writeup"
tags: ["crypto", "ecb", "cbc", "xor", "iced", "tea", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Hi All, Challenge description is like below:"
source:
  name: "CTFtime writeup #39344"
  url: "https://ctftime.org/writeup/39344"
original_source: "https://medium.com/@embossdotar/hackthebox-ctf-crypto-iced-tea-9a6a6c73094d"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Iced TEA"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Iced TEA
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39344>
- **Original writeup:** <https://medium.com/@embossdotar/hackthebox-ctf-crypto-iced-tea-9a6a6c73094d>

---
Hi All, Challenge description is like below:

"Locked within a cabin crafted entirely from ice, you’re enveloped in a chilling silence. Your eyes land upon an old notebook, its pages adorned with thousands of cryptic mathematical symbols. Tasked with deciphering these enigmatic glyphs to secure your escape, you set to work, your fingers tracing each intricate curve and line with determination. As you delve deeper into the mysterious symbols, you notice that patterns appear in several pages and a glimmer of hope begins to emerge. Time is flying and the temperature is dropping, will you make it before you become one with the cabin?  
Source: <https://ctf.hackthebox.com/event/details/cyber-apocalypse-2024-hacker-royale-1386> "

As you can see, with this task you have to download some files (crypto_iced_tea.zip). There are “output.txt” and “[source.py](http://source.py)” files.

“[source.py](http://source.py)” file:  
  
```  
import os  
from secret import FLAG  
from Crypto.Util.Padding import pad  
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b  
from enum import Enum

class Mode(Enum):  
ECB = 0x01  
CBC = 0x02

class Cipher:  
def __init__(self, key, iv=None):  
self.BLOCK_SIZE = 64  
self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]  
self.DELTA = 0x9e3779b9  
self.IV = iv  
if self.IV:  
self.mode = Mode.CBC  
else:  
self.mode = Mode.ECB

def _xor(self, a, b):  
return b’’.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

def encrypt(self, msg):  
msg = pad(msg, self.BLOCK_SIZE//8)  
blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]

ct = b’’  
if self.mode == Mode.ECB:  
for pt in blocks:  
ct += self.encrypt_block(pt)  
elif self.mode == Mode.CBC:  
X = self.IV  
for pt in blocks:  
enc_block = self.encrypt_block(self._xor(X, pt))  
ct += enc_block  
X = enc_block  
return ct

def encrypt_block(self, msg):  
m0 = b2l(msg[:4])  
m1 = b2l(msg[4:])  
K = self.KEY  
msk = (1 << (self.BLOCK_SIZE//2)) — 1

s = 0  
for i in range(32):  
s += self.DELTA  
m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])  
m0 &= msk  
m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])  
m1 &= msk

m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) — 1) # m = m0 || m1

return l2b(m)

if __name__ == ‘__main__’:  
KEY = os.urandom(16)  
cipher = Cipher(KEY)  
ct = cipher.encrypt(FLAG)  
with open(‘output.txt’, ‘w’) as f:  
f.write(f’Key : {KEY.hex()}\nCiphertext : {ct.hex()}’)  
```

and “output.txt” file:

```  
Key : 850c1413787c389e0b34437a6828a1b2  
Ciphertext : b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843  
```

This Python code implements a custom block cipher algorithm in two different modes: ECB (Electronic Codebook) and CBC (Cipher Block Chaining). The task seems to be about understanding how the encryption works and possibly breaking it to recover the original plaintext (the FLAG).

Let’s break down the code and understand its functionality:

(1) The Mode enum defines two encryption modes: ECB and CBC.

(2) The Cipher class represents the block cipher algorithm. It supports both ECB and CBC modes.

(3) The encrypt method of the Cipher class encrypts a given message using either ECB or CBC mode, depending on the initialization of the Cipher object.

(4) The encrypt_block method of the Cipher class performs the actual encryption of a single block using a custom block cipher algorithm.

(5) The __main__ block generates a random key, encrypts the FLAG using the Cipher class, and writes the key and ciphertext to the “output.txt” file.

To find the value of the FLAG, we need to decrypt the ciphertext provided in the “output.txt” file. The ciphertext is encrypted using the custom block cipher algorithm implemented in the “[source.py](http://source.py)” file.

Let’s decrypt the ciphertext using the Cipher class from the “[source.py](http://source.py)” file.

Solution — code (Python):

```  
import os  
from Crypto.Util.Padding import unpad  
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b  
from enum import Enum

class Mode(Enum):  
ECB = 0x01  
CBC = 0x02

class Cipher:  
def __init__(self, key, iv=None):  
self.BLOCK_SIZE = 64  
self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]  
self.DELTA = 0x9e3779b9  
self.IV = iv  
if self.IV:  
self.mode = Mode.CBC  
else:  
self.mode = Mode.ECB

def _xor(self, a, b):  
return b’’.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

def decrypt(self, ct):  
blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]

pt = b’’  
if self.mode == Mode.ECB:  
for ct_block in blocks:  
pt += self.decrypt_block(ct_block)  
elif self.mode == Mode.CBC:  
X = self.IV  
for ct_block in blocks:  
pt_block = self.decrypt_block(ct_block)  
pt += self._xor(X, pt_block)  
X = ct_block  
return unpad(pt, self.BLOCK_SIZE//8)

def decrypt_block(self, ct_block):  
c = b2l(ct_block)  
m0 = c >> (self.BLOCK_SIZE // 2)  
m1 = c & ((1 << (self.BLOCK_SIZE // 2)) — 1)  
K = self.KEY  
msk = (1 << (self.BLOCK_SIZE // 2)) — 1

s = (self.DELTA << 5) & msk  
for i in range(32):  
m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])  
m1 &= msk  
m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])  
m0 &= msk  
s -= self.DELTA  
s &= msk

return l2b(((m0 << (self.BLOCK_SIZE // 2)) + m1) & ((1 << self.BLOCK_SIZE) — 1))

if __name__ == ‘__main__’:  
#Key and ciphertext obtained from the “output.txt” file  
key_hex = ‘850c1413787c389e0b34437a6828a1b2’  
ct_hex = ‘b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843’

#Convert hexadecimal strings to bytes  
KEY = bytes.fromhex(key_hex)  
CT = bytes.fromhex(ct_hex)

#Decrypt the ciphertext  
cipher = Cipher(KEY)  
pt = cipher.decrypt(CT)

#Print the decrypted plaintext (FLAG)  
print(“FLAG:”, pt.decode())  
```

This script includes the decryption process within the same Python file. It directly reads the key and ciphertext from variables (key_hex and ct_hex) instead of reading them from an external file. After decrypting the ciphertext, it prints the decrypted plaintext, which is the FLAG.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*Qy5vv_vOoqFKePDLpq50zQ.png>)

Source: <https://jupyter.org/try-jupyter/notebooks/?path=Untitled.ipynb>

FLAG:

**HTB{th1s_1s_th3_t1ny_3ncryp710n_4lg0r1thm_y0u_m1ght_h4v3_4lr34dy_s7umbl3d_up0n_1t_1f_y0u_d0_r3v3rs1ng}**

Bonus info:

Block cipher mode of operation: <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation>

Electronic Code Book (ECB): <https://www.techtarget.com/searchsecurity/definition/Electronic-Code-Book>

Cipher Block Chaining (CBC): <https://www.techtarget.com/searchsecurity/definition/cipher-block-chaining>

Project Jupyter: <https://en.wikipedia.org/wiki/Project_Jupyter>

I hope you enjoy!
