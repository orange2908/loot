---
title: "steps - corCTF 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["diffie-hellman", "corctf", "crypto", "mathematics", "rsa", "aes", "sage", "xor", "proof-of-work", "corctf-2024", "2024", "ctf-writeup"]
summary: "Solves/Points: 99 solves / 129 points\\"
source:
  name: "CTFtime writeup #39357"
  url: "https://ctftime.org/writeup/39357"
original_source: "https://github.com/napwnli/napwnli_writeups/tree/main/Writeup/Crypto/Banana/Diffie-Hellman/corCTF2024%20Steps"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "steps"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** steps
- **Author team:** napwnli
- **CTFtime tags:** diffie-hellman, corctf, crypto, mathematics
- **CTFtime:** <https://ctftime.org/writeup/39357>
- **Original writeup:** <https://github.com/napwnli/napwnli_writeups/tree/main/Writeup/Crypto/Banana/Diffie-Hellman/corCTF2024%20Steps>

---
# Introduction  
Author: [Gifelaga](<https://github.com/Gifelaga>)\  
Name: crypto/steps\  
Solves/Points: 99 solves / 129 points\  
Description: Alice and Bob have taken steps to communicate securely.

This is the challenge source code:  
```py  
from Crypto.Util.number import getPrime  
from random import randint  
from hashlib import sha512  
from secret import FLAG

p = getPrime(1024)

Pair = tuple[int, int]

def apply(x: Pair, y: Pair) -> Pair:  
z0 = x[0] * y[1] + x[1] * y[0] - x[0] * y[0]  
z1 = x[0] * y[0] + x[1] * y[1]  
return z0 % p, z1 % p

def calculate(n: int) -> Pair:  
out = 0, 1  
base = 1, 1

while n > 0:  
if n & 1 == 1: out = apply(out, base)  
n >>= 1  
base = apply(base, base)

return out

def step(x: Pair, n: int):  
'''Performs n steps to x.'''  
return apply(x, calculate(n))

def xor(a: bytes, b: bytes) -> bytes:  
return bytes(i ^ j for i, j in zip(a, b))

def main() -> None:  
g = tuple(randint(0, p - 1) for _ in range(2))  
a = randint(0, p)  
b = randint(0, p)

A = step(g, a)  
B = step(g, b)

print(p)  
print(g)  
print(A)  
print(B)

shared = step(A, b)  
assert shared == step(B, a)

pad = sha512(str(shared).encode()).digest()  
print(xor(FLAG, pad))

if __name__ == "__main__":  
main()  
```  
We also got the output:  
```py  
140323158913416495607520736187548995477774864895449373468435168606940894555091715325755245563618777520381345121826124291879072024129139794758353829170487152290036863771427918014687523291663877491666410660298255515196964873944928956895167652588843616727666115196647426152811435167407394960435891152283442366721  
(96065253104055475368515351480749372850658086665031683689391433619786525841252022013348418216780129963411710917302022475212035579772549622047772413277044476931991100469638284113901919733675144788049607999711496364391389612383885735460390196619821411998848060208912802838145365054170790882835846039461477718592, 99241616571709523646659145402511086659276737895777010655080069795289409091105858433710404513588065826008320709508748555232998727290258965620812790826701703542423766306117851146140634247906095481346444357123297761881438234083584836393572339820023598801127329326758926529813665950889866710376403818615042210724)  
(70755695722452190644681854912493449110123792967984325777144153291795297730471865203878351550134745747839905472832417565386100721034554991782211134122667955909129461935072670637104557733518048519759925441567454988894610693095988261459294358350906447578625319131211019007537053689563772428590632011546870587548, 67209626648557152207459211543890871397518255584981755641031188457446084495247511864090204533159666638951190009379067537952490757956859052998865712873197974689323985952177932343928382624951392835548222455898153557185369330197085287972647654361464363270469055087587755117442462138962625643131163131541853061105)  
(112356264561144892053527289833892910675229600209578481387952173298070535545532140474473984252645999236867287593260325203405225799985387664655169620807429202440801811880698414710903311724048492305357174522756960623684589130082192061927190750200168319419891243856185874901350055033712921163239281745750477183871, 53362886892304808290625786352337191943295467155122569556336867663859530697649464591551819415844644455424276970213068575695727349121464360678240605137740996864232092508175716627306324344248722088013523622985501843963007084915323781694266339448976475002289825133821073110606693351553820493128680615728977879615)  
b'\xbaH\xca[V\xdf\xbb0d2jN"\x9d$e\xec\xe0M\x00\xdb\xf0\x8f\x99f\xc5\n\x8a\xc2h\xa7\xa7'  
```

# Description  
The challenge cryptosystem is divided in two steps:  
1\. A Diffie-Hellman like (**vulnerable**) key exchange between Alice and Bob.  
2\. A xor between the flag and the sha512 of the secret key.

Let's analyse the key exchange!\  
Firstly we've got a prime which will be used in the whole cryptosystem  
\- $p$: a 1024 bits prime

Then, each parameter is a tuple of two numbers:  
\- $g$: a tuple of two random numbers in the range [0, p - 1]  
\- $a$: a tuple of two random numbers in the range [0, p]  
\- $b$: a tuple of two random numbers in the range [0, p]

\- $A$ = step(g, a)  
\- $B$ = step(g, b)  
\- $K$ = step(A, b) == step(B, a)

As always in Diffie-Hellman key exchange, $(p, g, A, B)$ are the public parameters while $(a, b, K)$ are the private ones.

The step function returns `apply(x, calculate(n))`.\  
Where apply is the following function:  
```py  
def apply(x: Pair, y: Pair) -> Pair:  
z0 = x[0] * y[1] + x[1] * y[0] - x[0] * y[0]  
z1 = x[0] * y[0] + x[1] * y[1]  
return z0 % p, z1 % p  
```  
And calculate(n) returns a sort of OTP with the following function:  
```py  
def calculate(n: int) -> Pair:  
out = 0, 1  
base = 1, 1

while n > 0:  
if n & 1 == 1: out = apply(out, base)  
n >>= 1  
base = apply(base, base)

return out  
```

# Vulnerability  
The function `apply(x, y)` is easy to reverse, which a good cryptosystem should not be! (You cannot reverse AES, RSA or a good DH).

In mathematical terms this is the calculation:

$$ \begin{cases}  
z_0 \equiv x_0 \cdot y_1 + x_1 \cdot y_0 - x_0 \cdot y_0 \space (mod \space p) \newline  
z_1 \equiv x_0 \cdot y_0 + x_1 \cdot y_1 \space (mod \space p)  
\end{cases} $$

Where ( $z_0$ , $z_1$) is the output of the function `apply(x, y)` (also known as $A$ OR $B$), therefore we can solve the system in the variables ($y_0$, $y_1$), the secret key (obviously we also know the value of $g$ which is public).

So, knowing that $x_0=g_0, \space x_1=g_1$ and $z_0=A_0, \space z_1=A_1$ we are going to recover $y_0=calculate(a)_0, \space y_1=calculate(a)_1$ with some simple algebric steps.\  
From the system above, we get the following relations:

$$  
\begin{cases}  
y_1 \equiv [z_0 - (x_1-x_0) \cdot y_0] \cdot x_0^{-1} \space (mod \space p) \newline  
y_1 \equiv (z_1 - x_0 \cdot y_0) \cdot x_1^{-1} \space (mod \space p)  
\end{cases}  
$$

$$[z_0 - (x_1-x_0) \cdot y_0] \cdot x_0^{-1} \equiv (z_1 - x_0 \cdot y_0) \cdot x_1^{-1} \space (mod \space p)$$

$$[z_0 - (x_1-x_0) \cdot y_0] \cdot x_1 \equiv (z_1 - x_0 \cdot y_0) \cdot x_0 \space (mod \space p) =>$$

$$z_0 \cdot x_1 - (x_1-x_0) \cdot y_0 \cdot x_1 \equiv z_1 \cdot x_0 - x_0^2 \cdot y_0 \space (mod \space p) =>$$

$$y_0 \equiv (z_1 \cdot x_0 - z_0 \cdot x_1) \cdot (x_0^2 + x_0 \cdot x_1 - x_1^2)^{-1} \space (mod \space p)$$

Now we can just take $ K=apply(B, calculated(a)) => pad = sha512(str(K).encode()).digest() $ and so the flag:\  
$ ct \oplus pad=flag \oplus pad \oplus pad=flag $

# Exploit  
Here a working exploit:  
```py  
from hashlib import sha512

def apply(x, y):  
z0 = x[0] * y[1] + x[1] * y[0] - x[0] * y[0]  
z1 = x[0] * y[0] + x[1] * y[1]  
return z0 % p, z1 % p

def xor(a: bytes, b: bytes) -> bytes:  
return bytes(i ^ j for i, j in zip(a, b))

p = 140323158913416495607520736187548995477774864895449373468435168606940894555091715325755245563618777520381345121826124291879072024129139794758353829170487152290036863771427918014687523291663877491666410660298255515196964873944928956895167652588843616727666115196647426152811435167407394960435891152283442366721

g = (96065253104055475368515351480749372850658086665031683689391433619786525841252022013348418216780129963411710917302022475212035579772549622047772413277044476931991100469638284113901919733675144788049607999711496364391389612383885735460390196619821411998848060208912802838145365054170790882835846039461477718592, 99241616571709523646659145402511086659276737895777010655080069795289409091105858433710404513588065826008320709508748555232998727290258965620812790826701703542423766306117851146140634247906095481346444357123297761881438234083584836393572339820023598801127329326758926529813665950889866710376403818615042210724)  
A = (70755695722452190644681854912493449110123792967984325777144153291795297730471865203878351550134745747839905472832417565386100721034554991782211134122667955909129461935072670637104557733518048519759925441567454988894610693095988261459294358350906447578625319131211019007537053689563772428590632011546870587548, 67209626648557152207459211543890871397518255584981755641031188457446084495247511864090204533159666638951190009379067537952490757956859052998865712873197974689323985952177932343928382624951392835548222455898153557185369330197085287972647654361464363270469055087587755117442462138962625643131163131541853061105)  
B = (112356264561144892053527289833892910675229600209578481387952173298070535545532140474473984252645999236867287593260325203405225799985387664655169620807429202440801811880698414710903311724048492305357174522756960623684589130082192061927190750200168319419891243856185874901350055033712921163239281745750477183871, 53362886892304808290625786352337191943295467155122569556336867663859530697649464591551819415844644455424276970213068575695727349121464360678240605137740996864232092508175716627306324344248722088013523622985501843963007084915323781694266339448976475002289825133821073110606693351553820493128680615728977879615)

x0 = g[0]  
x1 = g[1]  
z0 = A[0]  
z1 = A[1]

'''  
somehow this does not work in sage, so I had to do it manually

from sage.all import *

y0, y1 = var('y0 y1')

eq1 = x0*y1 + x1*y0 - x0*y0 == z0  
eq2 = x0*y0 + x1*y1 == z1

solution = solve_mod([eq1, eq2], p)  
'''

# Skipping all the steps I put in the writeup  
# I love paper&pen crypto <3  
y0 = (z1*x0 - z0*x1) * pow(x0**2 + x0*x1 - x1**2, -1, p) % p  
y1 = (z1 - x0*y0) * pow(x1, -1, p) % p

calculated_a = (y0, y1)

shared = apply(B, calculated_a)

pad = sha512(str(shared).encode()).digest()

ct = b'\xbaH\xca[V\xdf\xbb0d2jN"\x9d$e\xec\xe0M\x00\xdb\xf0\x8f\x99f\xc5\n\x8a\xc2h\xa7\xa7'

print(xor(ct,pad)) # corctf{w4it_i7's_4ll_f1b0n4cci?}  
```
