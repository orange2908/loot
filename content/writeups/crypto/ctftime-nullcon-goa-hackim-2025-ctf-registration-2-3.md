---
title: "registration - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "format-string"
type: "writeup"
tags: ["crypto", "gcd", "sage", "format-string", "proof-of-work", "registration", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Here, we have a simple sig scheme."
source:
  name: "CTFtime writeup #39891"
  url: "https://ctftime.org/writeup/39891"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "registration"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** registration
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39891>

---
Here, we have a simple sig scheme.

If we somehow leak a\\*\\*d, we can make any signature by using `pow(a**d,hash(m),n)`

Lets suppose we get m1,m2 such that z1,z2=hash(m1),hash(m2) are coprime.  
This has a constant probability of happening.  
We then get x\\*z1+y\\*z2=1 for some integers x,y.

This means that `sig1**x * sig2**y= a**(d*(x*z1+y*z2)) = a**d mod n`  
Thus, we can forge signatures and get the flag.

```py  
from pwn import *  
from Crypto.Util.number import *  
from hashlib import sha256  
import math  
from sage.all import *

io=remote("52.59.124.14",5026)

def recvnum():  
io.recvuntil(b" = ")  
return int(io.recvline().decode(),10)

def recvnum2():  
io.recvuntil(b":")  
return int(io.recvline().decode(),10)

def recvby():  
io.recvuntil(b":")  
return bytes.fromhex(io.recvline().decode())

n=recvnum()  
a=recvnum()  
e=recvnum()

io.sendlineafter(b">",b"1")

chal1=recvby()  
chal1=bytes_to_long(sha256(chal1).digest())  
sig1=recvnum2()

print(pow(sig1,e,n))  
print(pow(a,chal1,n))

io.sendlineafter(b">",b"1")

chal2=recvby()  
chal2=bytes_to_long(sha256(chal2).digest())  
sig2=recvnum2()

print(math.gcd(chal1,chal2))

g,x,y=xgcd(chal1,chal2)

print(chal1*x+chal2*y)

ans=pow(sig1,x,n)*pow(sig2,y,n)  
ans%=n

print(pow(ans,e,n))  
print(a%n)

io.sendlineafter(b">",b"2")

chal3=recvby()

chal3=bytes_to_long(sha256(chal3).digest())

sig3=pow(ans,chal3,n)

io.sendlineafter(b":",str(sig3).encode())

io.interactive()  
```
