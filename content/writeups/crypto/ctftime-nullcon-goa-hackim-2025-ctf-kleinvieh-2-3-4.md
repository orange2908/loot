---
title: "kleinvieh - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "proof-of-work", "kleinvieh", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We are given strange = phi^2 = (pq - p - q + 1)^2 = (p + q - 1)^2 (mod n)."
source:
  name: "CTFtime writeup #39929"
  url: "https://ctftime.org/writeup/39929"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#kleinvieh"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "kleinvieh"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** kleinvieh
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39929>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#kleinvieh>

---
We are given `strange = phi^2 = (pq - p - q + 1)^2 = (p + q - 1)^2 (mod n)`. As the difference between `(p + q - 1)^2` and `strange` is small multiples of `n`, we can bruteforce the difference to recover `(p + q - 1)^2` and square root, then calculate `phi` to recover the flag.  
```python  
from math import isqrt  
from Crypto.Util.number import long_to_bytes

n = 123478096241280364670962652250405187135677205589718111459493149962577739081187795982860395854714430939628907753414209475535232237859888263943995193440085650470423977781096613357495769010922395819095023507620908240797541546863744965624796522452543464875196533943396427785995290939050936636955447563027745679377  
c = 77628487658893896220661847757290784292662262378387512724956478473883885554341297046249919230536341773341256727418777179462763043017367869438255024390966651705078565690271228162236626313519640870358976726577499711921457546321449494612008358074930154972571393221926233201707908214569445622263631145131680881658  
strange = 11519395324733889428998199861620021305356608571856051121451410451257032517261285528888324473164306329355782680120640320262135517302025844260832350017955127625053351256653287330703220294568460211384842833586028123185201232184080106340230097212868897257794101622865852490355812546172336607114197297201223620901

for i in range(10):  
pq1_sq = strange + i * n  
pq1 = isqrt(pq1_sq)  
if pq1 ** 2 == pq1_sq:  
print(f'{i = }')   
phi = n - pq1  
d = pow(65537, -1, phi)  
flag = pow(c, d, n)  
print(long_to_bytes(flag))  
break  
```
