---
title: "registration - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "format-string"
type: "writeup"
tags: ["crypto", "gcd", "format-string", "proof-of-work", "registration", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Welcome to our conference registration."
source:
  name: "CTFtime writeup #39963"
  url: "https://ctftime.org/writeup/39963"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "registration"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** registration
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39963>

---
# registration

## Description

Welcome to our conference registration. Please sign the given token, to verify that you are allowed to participate. If you cannot do so, let the people behind you register first.

connection : `nc 52.59.124.14 5026`

## Source

\- `[chall.py](http://chall.py)`  
```  
#!/bin/python3  
from hashlib import sha256  
from secret import flag  
from Crypto.Util import number  
import math  
import os

BITS = 1024

class Pubkey(object):  
def __init__(self, n, e, a):  
self.n = n  
self.a = a  
self.e = e

def verify(self, msg, s):  
if type(msg) == str: msg = msg.encode()  
h = number.bytes_to_long(sha256(msg).digest())  
return pow(s,self.e,self.n) == pow(self.a, h, self.n)

def __str__(self):  
return f'n = {self.n}\na = {self.a}\ne = {self.e}'

class Key(Pubkey):  
def __init__(self, bits):  
self.p = number.getPrime(bits >> 1)  
self.q = number.getPrime(bits >> 1)  
self.n = self.p * self.q  
phi = (self.p - 1) * (self.q - 1)  
while True:  
e = number.getRandomInteger(bits)  
if math.gcd(e, phi) == 1: break  
self.e = e  
self.d = number.inverse(e, phi)  
while True:  
a = number.getRandomInteger(bits)  
if math.gcd(a, self.n) == 1: break  
self.a = a

def sign(self, msg):  
if type(msg) == str: msg = msg.encode()  
h = number.bytes_to_long(sha256(msg).digest())  
return pow(self.a, h * self.d, self.n)

def public(self):  
return Pubkey(self.n, self.e, self.a)

def __str__(self):  
return f'n = {self.n}\na = {self.a}\ne = {self.e}\np = {self.p}'

if __name__ == '__main__':  
key = Key(BITS)  
print(key.public())  
while True:  
print('''Welcome to our conference reception. Can you provide a valid signature to confirm that you are alowed to participate? If not, please be patient and let the next person in the queue go fist.  
1) wait  
2) sign''')  
option = int(input('> '))  
if option == 1:  
challenge = os.urandom(BITS >> 3)  
signature = key.sign(challenge)  
print(f'Challenge: {challenge.hex()}')  
print(f'Signature: {signature}')  
elif option == 2:  
challenge = os.urandom(BITS >> 3)  
print(f'Challenge: {challenge.hex()}')  
signature = int(input('Signature: '))  
if key.verify(challenge, signature):  
print(flag)  
else:  
print('YOU SHALL NOT PASS!')  
break  
else:  
print('Invalid answer')  
break  
```

## Solution

\- This signature scheme uses somewhat of a diffie hellman encryption , where `g (generator)` is `a ** d mod n`, and the signature is generator from a message `m` by computing `g ** h mod n` where `h` is the `sha256` hash of `m`  
\- We have to generate a signature of a random message given to us without knowing the value of `d` to get the flag.  
\- If we have 2 hash values `h1` and `h2` such that their gcd is 1 and we have the respective signatures `g ** h1 mod n` and `g ** h2 mod n` then we can use euclid's extended gcd to get `a` and `b` such that `a * h1 - b * h2 = 1`.  
\- Then we can simply compute `s1 ** a * s2 ** (-b) mod n` to get `g ** 1 mod n` which is `g`.  
\- So, now we can get the signature of any message by calculating its `h` and then `s = g ** h mod n`

\- `[solve.py](http://solve.py)`  
```  
from pwn import *  
from Crypto.Util.number import *  
from hashlib import sha256

r = remote("52.59.124.14",5026)  
r.recvuntil(b' = ')  
n = int(r.recvline().strip().decode())  
r.recvuntil(b' = ')  
a = int(r.recvline().strip().decode())  
r.recvuntil(b' = ')  
e = int(r.recvline().strip().decode())

r.recvuntil(b'> ')  
r.sendline(b'1')  
r.recvuntil(b': ')  
c1 = bytes.fromhex(r.recvline().strip().decode())  
r.recvuntil(b': ')  
s1 = int(r.recvline().strip().decode())  
h1 = bytes_to_long(sha256(c1).digest())

r.recvuntil(b'> ')  
r.sendline(b'1')  
r.recvuntil(b': ')  
c2 = bytes.fromhex(r.recvline().strip().decode())  
r.recvuntil(b': ')  
s2 = int(r.recvline().strip().decode())  
h2 = bytes_to_long(sha256(c2).digest())

while math.gcd(h1,h2)!=1:  
r.recvuntil(b'> ')  
r.sendline(b'1')  
r.recvuntil(b': ')  
c2 = bytes.fromhex(r.recvline().strip().decode())  
r.recvuntil(b': ')  
s2 = int(r.recvline().strip().decode())  
h2 = bytes_to_long(sha256(c2).digest())

coeff1 = pow(h1,-1,h2)  
coeff2 = (coeff1 * h1 - 1)//h2

huan = (pow(s1,coeff1,n)*pow(pow(s2,-1,n),coeff2,n))%n  
r.recvuntil(b'> ')  
r.sendline(b'2')  
r.recvuntil(b': ')  
cc = bytes.fromhex(r.recvline().strip().decode())  
hh = bytes_to_long(sha256(cc).digest())  
ss = pow(huan,hh,n)  
r.recvuntil(b': ')  
r.sendline(str(ss).encode())  
r.interactive()  
```

## Flag  
`ENO{ha5h_ev3ryth1ng_th3y_s4id_s00o_s3cur3}`
