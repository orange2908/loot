---
title: "odd-bacon - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "speckcipher", "xor", "proof-of-work", "odd-bacon", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "First, notice that Enc(x)^Enc(y) elimintates the influence on k2."
source:
  name: "CTFtime writeup #39887"
  url: "https://ctftime.org/writeup/39887"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "odd-bacon"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** odd-bacon
- **Author team:** thehackerscrew
- **CTFtime tags:** speckcipher
- **CTFtime:** <https://ctftime.org/writeup/39887>

---
First step: MITM  
Let Enc(x)=F(x,k1,k2)  
First, notice that Enc(x)^Enc(y) elimintates the influence on k2.  
Therefore, we can consider Enc(x)^Enc(x^1) to reduce the search space.

That means that we can break the search on k1.  
We can ask for Enc(0),Enc(1),..., Enc(1024) and get 512 different values  
Then, we can bruteforce to guess the top bits, this takes pow(2,32)//1024=pow(2,22) operations.  
If we get a match, we can reconstruct k1 (up to parity)

```py  
from pwn import *  
from speck import SpeckCipher

def F(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).encrypt(int.from_bytes(block, byteorder = 'big')).to_bytes(4, byteorder = 'big')

def encrypt(msg : bytes, k1 : bytes, k2 : bytes):  
msg += b'0' * ((4 - (len(msg) % 4)) % 4)  
return (b''.join(xor(k2, F(xor(msg[i:i+4], k1))) for i in range(len(msg) // 4)))

from tqdm import *

io=remote('52.59.124.14',5033)  
# io=process(['python3','[chall.py](http://chall.py)'])  
flag=bytes.fromhex(io.recvline().decode())

ANS=[]  
D=dict({})  
for i in tqdm(range(1024)):  
io.sendlineafter(b">",p32(i).hex())  
ANS.append(bytes.fromhex(io.recvline()[1:-1].decode()))  
if i%2==1:  
D[xor(ANS[-2],ANS[-1])]=i

for i in tqdm(range(pow(2,32-10))):  
A=encrypt(p32(i*1024),b"\x00"*4,b"\x00"*4)  
B=encrypt(p32(i*1024+1),b"\x00"*4,b"\x00"*4)  
C=xor(A,B)  
if C in D:  
print("FOUND")  
print(i)  
print(D[C])  
print(ANS[0:10])  
print(flag)  
break  
```

Second part of exploit

With k1, we can then use the flag format to get k2, which means that we can then decrypt the flag by just reversing the operations since we know k1,k2

```py  
from pwn import *  
from speck import SpeckCipher

def F(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).encrypt(int.from_bytes(block, byteorder = 'big')).to_bytes(4, byteorder = 'big')

def Finv(block : bytes):  
return SpeckCipher(0x0123456789abcdef, key_size = 64, block_size = 32).decrypt(int.from_bytes(block, byteorder = 'big')).to_bytes(4, byteorder = 'big')

def encrypt(msg : bytes, k1 : bytes, k2 : bytes):  
msg += b'0' * ((4 - (len(msg) % 4)) % 4)  
return (b''.join(xor(k2, F(xor(msg[i:i+4], k1))) for i in range(len(msg) // 4)))

def decrypt(msg,k1,k2):  
msg=msg[:4]  
msg=xor(k2,msg)  
msg=Finv(msg)  
return xor(k1,msg)  


K=375094  
K*=1024  
K+=443  
K-=1

K=p32(K)

ANS=[b'$\x1ev\xe1', b'\r\xaf1I', b'\x146\xc5!', b'6\xc0\x82l', b'\xc2\xd3"\x99', b'\xda\x8a\xc6\x16', b'\xfa\x82\x81a', b'\xb9H\x93\xca', b',\xe2\x1f\xcb', b'k\xd1g6']  
flag=b'1%\x00\xdcs\xda\xffBnR\xdc\xf1\xaa\xc5x!\x12\xbc\xca\xb7\x88/o\x8c\x87^\x88\xea\x95\xa9\xc8\xca\\\\\x92\xdc\xa6\x9e\xd0Y\x1b\x93\x01\xc6~'

zero=p32(0)  
one=p32(1)  
#print(xor(encrypt(zero,K,b"\x00"),encrypt(one,K,b"\x00")))  
beg=b"ENO{"

U=encrypt(beg,K,b"\x00"*4)  
print(U)  
U=xor(U,flag[:4])

K2=U  
ans=b""  
for i in range(0,len(flag),4):  
ans+=decrypt(flag[i:i+4],K,K2)  
# print(decrypt(flag[4:8],K,K2))  
print(ans)  
```
