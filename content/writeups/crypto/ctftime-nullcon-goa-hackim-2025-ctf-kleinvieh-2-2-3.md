---
title: "kleinvieh_2 - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "coppersmith", "sage", "radare2", "proof-of-work", "low-exponent", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This is a combination of 5 smaller RSA challenges."
source:
  name: "CTFtime writeup #39925"
  url: "https://ctftime.org/writeup/39925"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#kleinvieh_2"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "kleinvieh_2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** kleinvieh_2
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39925>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#kleinvieh_2>

---
This is a combination of 5 smaller RSA challenges. The vulnerability and solution for each part is:  
1\. `c1 = m1^3` is smaller than `n`, so we can recover `m1` by taking cube root of `c1`,  
2\. `c2 = (m2 * r)^3`, so we can recover `m2^3 = c2 * r^(-3)`, then take cube root to find `m2`,  
3\. `c3 = (m3 * 256^493)^3`, the same as problem 2,  
4\. `c4 = (m3 * r2)^3` where `r2 = 1 + 256^18 + 256^36 + ... + 256^486`, same as problem 2,  
5\. `c5 = (m0 * 256^17 + m5)^3` where `m0 = bytes_to_long(b'\x42' * 494)` and `m5` is only 17 bytes, so use Coppersmith to recover `m5`.  
```python=  
from Crypto.PublicKey import RSA  
from Crypto.Util.number import bytes_to_long, long_to_bytes  
from sage.all import *

def fr(x, n):  
return Integer(x).nth_root(n, truncate_mode=True)[0]

with open('pubkey.pem', 'rb') as f:  
key = RSA.import_key(f.read())  
n, e = key.n, key.e

with open('output', 'r') as f:  
cts = list(map(int, f.read().splitlines()))

c1, c2, c3, c4, c5 = cts  
m1 = long_to_bytes(fr(c1, 3))  
print(m1)

r = 688234005348009046360676388021599552323079007705479727954148955984833460337936950913921276804334830417982234720038650432729780498514155995618937412575604196815690605161835755609341381092145548153312943119696398326144902639226831471200542337105282064399184931676924592908530791494346900227871404063095592748764296028255530577278656680463782655139421219302422899667665339277824718421901831817043159552132252016945226370677278067424506514993298100924479619565269428391036310378044733517453768164252655931111202089432697078947184486267865943138659836155939343134738408972426979329158506027280653209318479413895259774319848662706808171929571545923310500352950348748809789292920278241362015278963315481777028997344480172010960294002098578989469089294022590134823913936869548907125294447477430739096767474026401347928008150737871869441842515706902681140123776591020038755234642184699856517326004574393922162918839396336541620212296870832659576195010466896701249003808553560895239860454162846759635434691728716499056221797005696650174933343585361153344017021747827389193405667073333443569659567562247406283282451284155149780737904760989910944550499316655128394899229284796584787198689342431338201610314893908441661953172106881929330452489260  
r_cubed = pow(r, 3, n)  
inv_r_cubed = pow(r_cubed, -1, n)  
m2_cubed = (c2 * inv_r_cubed) % n  
m2 = long_to_bytes(fr(m2_cubed, 3))  
print(m2)

m3 = c3 * pow(256, -(511 - 18) * 3, n) % n  
m3 = long_to_bytes(fr(m3,3))  
print(m3)

step = 256 ** 18  
t = step  
k = 1  
for i in range(27):  
k += step  
step = step * t % n  
k %= n  
m4 = c4 * pow(k, -3, n) % n  
m4 = fr(m4, 3)  
m4 = long_to_bytes(m4)  
print(m4)

P = PolynomialRing(Zmod(n), 'x')  
x = P.gen(0)  
f = (bytes_to_long(b'\x42' * 494) * 256 ** 17 + x) ** 3 - c5  
m5 = long_to_bytes(int(f.small_roots(X = 256 ** 17, epsilon = 0.1)[0]))

flag = m1 + m2 + m3 + m4 + m5  
print(flag)  
```
