---
title: "next-level - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "prime", "proof-of-work", "next-level", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This function is non decreasing."
source:
  name: "CTFtime writeup #39892"
  url: "https://ctftime.org/writeup/39892"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "next-level"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** next-level
- **Author team:** thehackerscrew
- **CTFtime tags:** prime
- **CTFtime:** <https://ctftime.org/writeup/39892>

---
next()= next prime.  
This function is non decreasing.  
In this challenge the function p\\*next(p)\\*next(next(p)) is the product of three positive non decreasing functions, therefore its non decreasing.  
This means we can use binary search to get p, and then get the factorization, which gives us the private key and the flag.

```py  
lo=0  
hi=pow(2,512)

n=390652869118399431956324800559151791084500222679076986550352828908429378385587241455564202569211806474681108522885210749147966420589741574519187219302548091208401984394809644977250356152427947763251612969042786297152303224231502370780655803329478291643075610195081325494850303896618822712996322145411690648689760200811664173576547196090113921645369842759681056188830276669016408393899385793005442247246093975283935379637182647452658580288200917272311131715088949  
c=212696093257843068014400629563699153612883710295330984631529729378660689228574808893494188520617130385490974048486353172307654508648469764446785078624785425944604146383179074703485105222525997550455933218059394392335664639605508028965084436849133738156877684862814847767356981317534327179081661250718344630574169352952695296279186704158498725316770299782809025448477332961208077509932740150210050228104760176279999887657499067415573437908401036234329540587574663  
from Crypto.Util import number

def nextprime(n):  
p = n  
while True:  
if number.isPrime(p := p+1): return p

while hi-lo>1:  
print(hi,lo)  
p=(hi+lo)//2  
q = nextprime(p)  
r = nextprime(q)  
N = p*q*r  
if N>n:  
hi=p  
elif N
