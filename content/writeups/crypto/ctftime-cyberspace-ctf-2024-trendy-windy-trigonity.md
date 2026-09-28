---
title: "trendy windy trigonity - CyberSpace CTF 2024"
category: "crypto"
subcategory: "lattice"
type: "writeup"
tags: ["crypto", "lll", "trendy", "windy", "trigonity", "lattice", "cyberspace-ctf", "cyberspace-ctf-2024", "2024", "ctf-writeup"]
summary: "from Crypto.Util.number import longtobytes"
source:
  name: "CTFtime writeup #39433"
  url: "https://ctftime.org/writeup/39433"
original_source: "https://github.com/Team-Kirby/csctf-2024-writeups/blob/main/crypto/trendy%20windy%20trigonity/solve.sage"
ctf:
  name: "CyberSpace CTF 2024"
  year: 2024
  challenge: "trendy windy trigonity"
---

## Metadata

- **CTF:** CyberSpace CTF 2024
- **Task:** trendy windy trigonity
- **Author team:** Team Kirby
- **CTFtime tags:** crypto, lll
- **CTFtime:** <https://ctftime.org/writeup/39433>
- **Original writeup:** <https://github.com/Team-Kirby/csctf-2024-writeups/blob/main/crypto/trendy%20windy%20trigonity/solve.sage>

---
``` python3  
from Crypto.Util.number import long_to_bytes

m = 10 ** 300 # both enc and x has a decimal point of 300  
R = RealField(1000)  
enc = R(2.78332652222000091147933689155414792020338527644698903976732528036823470890155538913578083110732846416012108159157421703264608723649277363079905992717518852564589901390988865009495918051490722972227485851595410047572144567706501150041757189923387228097603575500648300998275877439215112961273516978501e45)  
x = R(0.75872961153339387563860550178464795474547887323678173252494265684893323654606628651427151866818730100357590296863274236719073684620030717141521941211167282170567424114270941542016135979438271439047194028943997508126389603529160316379547558098144713802870753946485296790294770557302303874143106908193100)

# Convert them all to int as LLL doesn't work on real  
y = int(enc * m)  
cos_x = int(cos(x) * m)  
sin_x = int(sin(x) * m)

K = 1  
M = Matrix([  
[1, 0, 0, cos_x],  
[0, 1, 0, sin_x],  
[0, 0, 1, y],  
])  
r = M.LLL().rows()[0]  
flag = long_to_bytes(abs(int(r[0]))) + long_to_bytes(abs(int(r[1])))  
print(flag)  
```
