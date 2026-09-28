---
title: "Trypanophobia - BlackHat MEA CTF Qualification 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "cryptography", "padding", "rsa", "sage", "proof-of-work", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "Difficulty: Easy - 120pts"
source:
  name: "CTFtime writeup #39410"
  url: "https://ctftime.org/writeup/39410"
original_source: "https://medium.com/@irenavk/black-hat-mea-ctf-2024-quals-crypto-writeups-26f341a971b6"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Trypanophobia"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Trypanophobia
- **Author team:** V3n0m.py
- **CTFtime tags:** cryptography, padding, rsa
- **CTFtime:** <https://ctftime.org/writeup/39410>
- **Original writeup:** <https://medium.com/@irenavk/black-hat-mea-ctf-2024-quals-crypto-writeups-26f341a971b6>

---
# Trypanophobia   
**Category:** Crypto

**Difficulty:** Easy — 120pts

**Description:** Sit still, okay? It’ll be over quick, and furthermore, it’s just a lil’ prick.

The code might be a bit long, but it’s relatively simple. Let’s break it down. 

The code defines a generic RSA encryption object but with some caveats:  
```python  
def update(self):  
self.public['n'] = 1  
self.private['f'] = 1  
for p in self.private['p']:  
self.public['n'] *= p  
self.private['f'] *= (p - 1)  
self.private['d'] = inverse(self.public['e'], self.private['f'])  
```  
First, there’s this update function that appends the primes we provide the server to its public key primes, then recalculates n, phi and the private exponent.  
```python  
def pad(self, x):  
y = int(hashlib.sha256(str(set(self.private['p'])).encode()).hexdigest(), 16)  
while x < self.public['n']:  
x *= y  
x //= y  
return x  
```  
This function uses the hash of all primes in a set (so only unique values), and uses it to pad the plaintext until it’s just smaller than n.  
```python  
# Server loop  
TUI = "|\n| Menu:\n| [A]dd a key\n| [E]ncrypt flag\n| [Q]uit\n|"

while True:  
try:

print(TUI)  
choice = input("| > ").lower()

if choice == 'q':  
print('|\n| [~] Goodbye ~ !\n|')  
break  
  
elif choice == 'a':  
uin = json.loads(input("| > (JSON) "))  
assert uin.keys() == {'p', 'q'}  
if all([  
isPrime(uin['p']), isPrime(uin['q']),  
len(bin(uin['p'])) == 1024 + 2,  
len(bin(uin['q'])) == 1024 + 2  
]):  
ourKey.private['p'] += [uin['p'], uin['q']]  
ourKey.update()  
else:  
print('| [!] Invalid primes.')

elif choice == 'e':  
enc = ourKey.encrypt(int.from_bytes(FLAG, 'big'))  
print('| Flag = 0x{:x}'.format(enc))  
```  
Then we have the main server loop that allows us to add our own p, q pair to RSA object after doing some checks, and an option to print the encrypted flag back to us.

Now that we know the gist of the code, let’s see how to exploit this:

If we supply prime factors that we know, we can simplify the modulus as such:

$$C=m^e \bmod (p \times q \times r \times r)$$

$$m^e \bmod (p \times q \times r \times r) \equiv m^e \bmod (r \times r)$$

$$C' = C \bmod r$$

$$\phi(r) = r - 1$$

$$d \times e \equiv \bmod \phi(r)$$

$$m = C'^d \bmod r$$

Since we can also supply the same prime twice, if we keep sending the same prime over and over, the hash of the primes won’t change, the padding will only be multiplied more. By experimenting a little with the code, I found it usually took 14 rounds after adding the first pair, then 22, then 30, then 38, and so on.

Let padding = $y$

$$c1 = (m \times y^14)^e \bmod (n \times r \times r)$$

$$c2 = (m \times y^22)^e \bmod (n \times r \times r \times r \times r)$$

By applying the simplification above,

$$c1 \bmod r = (m \times y^14)^e \bmod r$$  
$$c2 \bmod r = (m \times y^22)^e \bmod r$$

Then decrypting using the private modulus we calculated:

$$m1 = c1^d \bmod r$$

$$m2 = c2^d \bmod r$$

$$m1 = (m \times y^14) \bmod r$$

$$m2 = (m \times y^22) \bmod r$$

Then if we multiply m2 by the modular inverse of m1, we’ll get y⁸, calculate the modular square root 4 times and we get the padding value. Then we calculate m!  
```python  
from Crypto.Util.number import inverse  
from sympy import nextprime  
from Crypto.Util.number import long_to_bytes  
from sage.all import *

e = 0x10001

start = 2**1023  
r = nextprime(start)  
print('{"p":'+r+',"q":'+r+'}') 

c1 = ... # Fill from code after sending JSON 1st time and choosing e  
c2 = ... # Fill from code after sending JSON 2nd time and choosing e

buf1 = c1 % r  
buf2 = c2 % r

phi = (r-1)  
d = inverse(e, phi)

m1 = pow(buf1, d, r)  
m2 = pow(buf2, d, r)

# Divide m2 by m1  
y8 = m2 * inverse(m1, r) % r

# Calculate 8th root (i.e. square root 4 times)  
y = sqrt(y8) % r  
y = sqrt(x) % r  
y = sqrt(x) % r

m = m1//y**14

print(long_to_bytes(m))  
```
