---
title: "coinflip - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "gcd", "proof-of-work", "coinflip", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We can recover multiples of m by getting 3 consecutive states s0, s1, s2 => k  m = s0  3  s2 - s1  4."
source:
  name: "CTFtime writeup #39924"
  url: "https://ctftime.org/writeup/39924"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#coinflip"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "coinflip"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** coinflip
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39924>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#coinflip>

---
We can recover multiples of `m` by getting 3 consecutive states `s0, s1, s2` => `k * m = s0 ** 3 * s2 - s1 ** 4`. By constantly sending `head`, praying to get 4 consecutive states, we can firmly recover `m = gcd(s0 ** 3 * s2 - s1 ** 4, s1 ** 3 * s3 - s2 ** 4)`. Then `a = s1 * s0 ^ -3 (mod m)`. After that we can know the next state of RNG, bet all the money each time and get the flag.  
```python=  
from pwnlib.tubes.remote import remote

from math import gcd  
from Crypto.Util.number import bytes_to_long, getRandomNBitInteger  
import math  
import os  
class CRG(object):  
def __init__(self, n):  
self.n = n  
self.m = getRandomNBitInteger(n)  
while True:  
self.a = bytes_to_long(os.urandom(n >> 3)) % self.m # n/8 bytes  
if math.gcd(self.a, self.m) == 1: break  
while True:  
self.state = bytes_to_long(os.urandom(n >> 3)) % self.m # n/8 bytes  
if math.gcd(self.state, self.m) == 1: break  
self.buffer = []  
  
def next(self):  
if self.buffer == []:  
self.buffer = [int(bit) for bit in bin(self.state)[2:].zfill(self.n)]  
self.state = self.a * pow(self.state, 3, self.m) % self.m  
return self.buffer.pop(0)

while True:

io = remote("52.59.124.14", 5032)  
bits = []  
try:  
for _ in range(256):  
line = io.recvuntil(b')', timeout=1)  
balance = int(line.decode().strip().split()[-1][:-1])  
if line == b'':  
break  
io.sendline(b'1')  
io.sendlineafter(b'?\n', b'head')  
if b'win' in io.recvline():  
bits.append('0')  
else:  
bits.append('1')  
break  
except EOFError:  
print(f'{_ = }')  
io.close()  
continue  
s1 = int(''.join(bits[:64]), 2)  
s2 = int(''.join(bits[64:128]), 2)  
s3 = int(''.join(bits[128:192]), 2)  
s4 = int(''.join(bits[192:]), 2)  
m = gcd(s1 ** 3 * s3 - s2 ** 4, s2 ** 3 * s4- s3 ** 4)  
print(f'{balance = }')  
print(m.bit_length())  
print(m)  
crg = CRG(64)  
crg.m = m  
crg.a = s2 * pow(s1, -3, m) % m  
crg.state = (crg.a * pow(s4, 3, m)) % m

coin = [b'head',b'tails']

for _ in range(30 - int(math.log2(balance))):  
line = io.recvuntil(b')')  
balance = int(line.decode().strip().split()[-1][:-1])  
print(f'{balance = }')  
io.sendline(str(balance).encode())  
  
io.sendlineafter(b'?\n', coin[crg.next()])  
io.recvline()  
io.interactive()  
```
