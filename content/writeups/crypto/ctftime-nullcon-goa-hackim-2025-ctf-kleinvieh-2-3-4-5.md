---
title: "kleinvieh - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "proof-of-work", "kleinvieh", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "In this chall, we are given phi^2 mod n."
source:
  name: "CTFtime writeup #39890"
  url: "https://ctftime.org/writeup/39890"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "kleinvieh"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** kleinvieh
- **Author team:** thehackerscrew
- **CTFtime tags:** rsa
- **CTFtime:** <https://ctftime.org/writeup/39890>

---
In this chall, we are given phi^2 mod n.  
Since phi=p\\*q-p-q+1, then phi^2=(-p-q+1)^2=(p+q-1)^2 mod n.  
Since p,q are approximately sqrt(n), (p+q-1)^2 should be on the order of n.  
Therefore, we may bruteforce numbers on the form strange+k\\*n, and for a small k we get a square number.  
Then, since we know the sum and product of primes, we can solve a quadratic equation to get them both.

```py  
from sympy import *

n = 123478096241280364670962652250405187135677205589718111459493149962577739081187795982860395854714430939628907753414209475535232237859888263943995193440085650470423977781096613357495769010922395819095023507620908240797541546863744965624796522452543464875196533943396427785995290939050936636955447563027745679377  
c = 77628487658893896220661847757290784292662262378387512724956478473883885554341297046249919230536341773341256727418777179462763043017367869438255024390966651705078565690271228162236626313519640870358976726577499711921457546321449494612008358074930154972571393221926233201707908214569445622263631145131680881658  
strange = 11519395324733889428998199861620021305356608571856051121451410451257032517261285528888324473164306329355782680120640320262135517302025844260832350017955127625053351256653287330703220294568460211384842833586028123185201232184080106340230097212868897257794101622865852490355812546172336607114197297201223620901

#(p+q-1)^2=p^2+q^2+2*p*q+1-2*p-2*q

for k in range(1000):  
U=strange+n*k  
C=integer_nthroot(U, 2)  
if C[1]:  
print(C)  
break  
sm=C[0]+1

pr=n

delta=integer_nthroot(sm**2-4*pr, 2)[0]

p=(sm+delta)//2  
q=(sm-delta)//2

phi=(p-1)*(q-1)

d=pow(0x10001,-1,phi)

from Crypto.Util.number import *

print(long_to_bytes(pow(c,d,n)))  
```
