---
title: "Alter Ego - SekaiCTF 2025"
category: "crypto"
type: "writeup"
tags: ["crypto", "csidh", "sage", "eval", "alter", "ego", "sekaictf", "sekaictf-2025", "2025", "ctf-writeup"]
summary: "The challenge required to find a CSIDH secret key with coefficients in [-30,-1] equivalent to a hidden CSIDH key with coefficients in [12,27]."
source:
  name: "CTFtime writeup #40392"
  url: "https://ctftime.org/writeup/40392"
ctf:
  name: "SekaiCTF 2025"
  year: 2025
  challenge: "Alter Ego"
---

## Metadata

- **CTF:** SekaiCTF 2025
- **Task:** Alter Ego
- **Author team:** organizers
- **CTFtime tags:** csidh
- **CTFtime:** <https://ctftime.org/writeup/40392>

---
# Alter-ego writeup

## 1. Understanding the challenge

The challenge required to find a [CSIDH](<https://eprint.iacr.org/2018/383.pdf>) secret key with coefficients in [-30,-1] equivalent to a hidden CSIDH key with coefficients in [12,27]. To do so, there is access to an oracle for 39 queries in total. 

The oracle evaluates for each query a hidden key sk' on a on the curve it last output (or a fixed supersinglar curve E0 if it is the first oracle call). A single uniformly random point of the curve considered over F_p^2 is mapped through sk', and the resulting curve and point are returned (but not the input). The evaluation is done in x-only arithmetic, and the output normalized before being returned. The key sk' is initially equal to the key sk to be guessed, but the player can modify it after each round by adding to each coefficient a value in {-1,0,1}.

## 2. Solve simpler problems

Sometimes it is easier to solve a problem piece-wise, so lets try to see if there is simpler subparts or variants of this.

### 2.a Given the secret

First, notice that if sk was known, finding the equivalent key could be done using techniques from this [paper](<https://eprint.iacr.org/2019/1209>). More precisely, since any multiple of the all-three coefficient vector is an endomorphism, a secret key can be altered by any multiple of [3,...3] without changing the corresponding secret key. So if sk is the secret key with coefficients in [12,27], then a solution would be sk-[30,...,30]. This can be tested experimentally in sage.

### 2.b Given two random point images

Second, imaging that the oracle gives us the image of 2 random points instead of one. A uniformly random point is most likely of order l_1...l_k if l_1,...,l_k are the prime factors of the curve order used in CSIDH. Multiplying it by all of the l_i except one noted l_e therefore a uniformly random point of order (1 or) l_e. Over F_p^2, it is unlikely that two random points of order l_e are in the same cyclic subgroup of order l_e. If they are not, then their images through an isogeny phi are in the same cyclic subgoup if and only if l_e divides the degree of phi, so if and only if the coefficient for l_e in phi is not 0. 

Since isogenies are linear, it is possible to compute from a the image of a single uniformly random point of order l_1...l_k, the images of a uniformly random point of order l_e for all prime factors l_e of the coefficients. This is done by multiplying the image by all other primes dividing the curve order. Therefore, the image of 2 uniformly random points on a curve by an isogeny phi (without these initial points) is enough to test for all l_e at once whether their coefficients in phi are zero. 

Therefore, with the 39 accesses to the oracle and knowing that the coefficients of sk are in [12,27], it is possible to simply add [-1,...,-1] to sk after every oracle call, and observe at which call the coefficient of each l_i becomes 0 (for a single round, since negative coefficients behave like positive ones here). This round number is equal to the coefficient of the l_i in sk.

Since the random points can accidentally have order not exactly l_1...l_k but only a divisor of it, it is possible that there are false positives sometimes. This can mostly be detected by checking if one of the two images is the point at infinity for some l_i. In this case, the result could be a zero, but most likely it is not. Therefore, if no zero is measured in all oracle calls, then the round numbers where a point at infinity occurred can be hiding the zero. In practice however, even when discarding (and counting as non-zeros) all occurrences of the point at infinity, one can most often recover all coefficients, as tested experimentally. And if one is unlucky, one can just rerun the attack against a new instance until recovering a full secret. 

Combining the 0-detection method for recovering sk's coefficients with the method from 2.a to find the solution once sk is known, we therefore could solve the challenge if the oracle gave us 2 solutions instead of one. 

### Conclusion

We now know that we only need to find a way to detect zero coefficients given the image of a single random point (so the real oracle output) in order to solve alter-ego.

## 3. Solution

### 3.a One-image zero detection

At this point, it might be time to just play around with sage. Use the given setup, look at the image of a few random points (after multiplying by all l_i except one noted l_e), and see if there is a noticeable difference between the cases there the coefficient of l_i is zero and where it is not. 

The following striking observation can be made: If the coefficient is at least 1, then the image of a random point of order l_e over F_p^2 as output by the group action evaluated implementation provided is always of the form (x,iy) where x and y are in F_p (after translating back to Weierstrass coordinates as normal in sage). 

Even without understanding the reason for this, the observation is sufficient to distinguish between coefficients >=1 and <= 0 for all l_i given the image of a single unknown point P of order l_1...l_k. We can now use the techniques from 2.b, except that the zero-detection using the images of 2 points can now be replaced with a test whether, for the image P of a random point over F_p^2, ((p+1)/l_e)P is of the form (x,iy) for x,y in F_p, in which case the coefficient of l_e is at least 1. Again, to minimize errors, the point at infinity is always ignored. Furthermore, we now record the oracle call number of the first occurrence of a coefficient not >=1 as the coefficient of l_e in the secret. Again, bad luck can make our search fail, but it is unlikely enough that just rerunning the attack should fix it. 

### 3.b Implementation

So now we only need to script the interaction with the remote. This fairly simple part sadly delayed us too much from actually getting the flag during the game time. We still obtained it withing the following quarter of an hour. I never got to run this script and I thank my teammates who helped me to piece it together.

The obtained flag is:  
`SEKAI{With_zero_oxygen_remaining,_I_want_to_be_able_to_say_'that_was_an_amazing_game'_with_my_final_breath._https://[youtu.be/qo6e2tiVEeo](https://youtu.be/qo6e2tiVEeo)}`

```py

from pwn import *

from random import randint  
import os

proof.arithmetic(False)

MI = 3  
KU = 9  
MIKU = 39

ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]  
p = 4 * prod(ells) - 1

Fp = GF(p)  
F = GF(p**2, modulus=x**2 + 1, names='i')  
i = F.gen(0)  
E0 = EllipticCurve(F, [1, 0])  
E0.set_order((p + 1)**2)

HOST = "alter-ego.chals.sekai.team"  
PORT = "1337"

P = remote(HOST,PORT,ssl=True)  
  
Gs = []  
Es = []  
for mik in range(39):  
Es.append(P.recvline_contains(b"final_a2"))#receive E  
Gs.append(P.recvline_contains(b"_final_G"))#receive G  
P.sendline(", ".join(map(str,[-1]*74)))#send sequence  
  
print(Gs)  
print(Es)

import re

res = [[False for x in range(74)] for y in range(39)]   
for I in range(39):  
G = list(map(int, re.findall("\d+", Gs[I])))  
a2 = int(Es[I].strip().split()[-1])  
EllipticCurve(F, [0, a2, 0, 1, 0])  
  
Gx = F(eval(Gx))  
Gz = F(eval(Gz))  
Gf = E.lift_x(Gx/Gz)  
for ell in range(len(ells)):  
Gfl = ((p+1)/ells[ell])*Gf  
if not (Gfl.is_zero()) and not((Gfl.x() in Fp) and I*Gfl.y() in Fp):  
res[I][ell] = True  
print(res[I])  
  


r = [-1 for ell in range(len(ells))]  
for e in range (len(ells)):  
for mik in range(MIKU):  
if(res[mik][e]):  
r[e]=mik-30  
break  
  
P.sendlineafter(b">", ", ".join(map(str,r)))  
P.interactive()

``` 

### Further thoughts

The zero-dection in 3.a uses a difference in the "positive" and "negative" directions in CSIDH. Knowing that the positive direction uses isogenies whose kernels are defined over F_p, one could maybe have guessed that the images in this case are not defined over F_p, but look somehow "orthogonal" to it.
