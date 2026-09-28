---
title: "odd-bacon - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "xor", "proof-of-work", "odd-bacon", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "There is something wrong with the author."
source:
  name: "CTFtime writeup #39951"
  url: "https://ctftime.org/writeup/39951"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "odd-bacon"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** odd-bacon
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39951>

---
# odd-bacon

## Description

There is something wrong with the author. He uses a cipher that is essentially called "bacon", he uses a publicly known key and then he claims that there even is a security proof for this kind of cipher.

connection : `nc 52.59.124.14 5033`

## Source

\- `[chall.py](http://chall.py)`

```  
import os  
from pwn import xor  
from speck import SpeckCipher

def F(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).encrypt(int.from_bytes(block, byteorder = 'big')).to_bytes(4, byteorder = 'big')

def encrypt(msg : bytes, k1 : bytes, k2 : bytes):  
msg += b'0' * ((4 - (len(msg) % 4)) % 4)  
return (b''.join(xor(k2, F(xor(msg[4*i:4*i+4], k1))) for i in range(len(msg) // 4))).hex()

if __name__ == '__main__':  
N = 1024  
k1 = os.urandom(4)  
k2 = os.urandom(4)  
flag = open('flag.txt','r').read().strip().encode()  
print(encrypt(flag, k1, k2))  
for _ in range(N):  
print('Please enter your chosen plaintext')  
try:  
user_input = input('> ')  
if user_input == 'exit': break  
assert len(user_input) == 8  
msg = bytes.fromhex(user_input)  
print(encrypt(msg, k1, k2))  
except:  
print('Could not get message')  
```

## Solution

\- The encrypt function takes blocks of 4 bytes length, xors it with the same key and then after speck encryption xors it with another *same key.  
\- Lets say we have two messages of 4 byte length (m1 and m2) and the result from encrypt function is e1 and e2 , then e1 ^ e2 = speck(m1 ^ k1) ^ speck(m2 ^ k1)  
\- So, if we send m1 and m2 such that m1^m2 == 1, the e1 ^ e2 will be speck(a) ^ speck(a^1)  
\- If we have speck(a) ^ speck(a^1) stored for multiple a's then we can extract k1 as a^m1.

\- In one instance of the server it allows 1024 messages, so we can send 512 pairs of m , (m^1).  
\- 4 bytes of messages have `2**32` possibilities, so if we send the `2**9` ( 512 ) messages at equal distance then we will need to store the pairs of speck(a) ^ speck(a^1) for the firt `2**23` numbers

\- `[generate.py](http://generate.py)`  
```  
from speck import SpeckCipher

def F(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).encrypt(block)

def F2(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).decrypt(block)

arr = dict()  
for i in range(pow(2,22)):  
if(i%100000)==0:  
print(f'{i = }')  
arr[F(2*i)^F(2*i+1)] = i

open('[arar.py](http://arar.py)','w').write(f'{arr = }')  
```

\- `[solve.py](http://solve.py)`  
```  
import os  
from speck import SpeckCipher

def F(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).encrypt(block)

def F2(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).decrypt(block)

from pwn import *  
from Crypto.Util.number import *  
print('starting')  
arr = open('[arar.py](http://arar.py)','r').read()  
print('ok')

r = remote("52.59.124.14",5033)  
a = r.recvline().decode().strip()  
cts = [int(a[i:i+8],16) for i in range(0,len(a),8)]  
eno = bytes_to_long(b'ENO{')  
flag1 = flag2 = b'ENO{'  
mult = pow(2,23)  
for i in range(512):  
if i%32==0:  
print(f'{i = }')  
r.recvuntil(b'> ')  
r.sendline(hex(i*mult)[2:].zfill(8).encode())  
res1 = int(r.recvline().decode().strip(),16)  
r.recvuntil(b'> ')  
r.sendline(hex((i*mult)^1)[2:].zfill(8).encode())  
res2 = int(r.recvline().decode().strip(),16)  
rr=res2^res1  
if str(rr) in arr:  
try:  
ind = arr.index(str(rr))  
print(rr,arr[ind-5:ind+20])  
num = int(arr[ind:ind+20].split(': ')[1].split(',')[0])*2  
k1 = num^(i*mult)  
k2 = cts[0]^F(k1^eno)  
print(f"{k1,k2 = }")  
for i in range(1,len(cts)):  
flag1+=long_to_bytes(F2(cts[i]^k2)^k1)  
k1 = num^(i*mult)^1  
k2 = cts[0]^F(k1^eno)  
print(f"{k1,k2 = }")  
for i in range(1,len(cts)):  
flag2+=long_to_bytes(F2(cts[i]^k2)^k1)  
print(f'{flag1 = }')  
print(f'{flag2 = }')  
flag1 = flag2 = b'ENO{'  
except:  
continue  
```
