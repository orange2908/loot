---
title: "ModulusRSA - CyberSpace CTF 2024"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "proof-of-work", "modulusrsa", "pow", "cyberspace-ctf", "cyberspace-ctf-2024", "2024", "ctf-writeup"]
summary: "from Crypto.Util.number import longtobytes"
source:
  name: "CTFtime writeup #39438"
  url: "https://ctftime.org/writeup/39438"
ctf:
  name: "CyberSpace CTF 2024"
  year: 2024
  challenge: "ModulusRSA"
---

## Metadata

- **CTF:** CyberSpace CTF 2024
- **Task:** ModulusRSA
- **Author team:** RedHazzarTeam
- **CTFtime:** <https://ctftime.org/writeup/39438>

---
```  
from Crypto.Util.number import long_to_bytes

e = 65537  
w = 115017953136750842312826274882950615840  
x = 16700949197226085826583888467555942943  
y = 20681722155136911131278141581010571320  
c = 2246028367836066762231325616808997113924108877001369440213213182152044731534905739635043920048066680458409222434813

for k1 in range(1,200):  
for k3 in range(1,200):  
for k2 in range(k1*k3,(k1+k3)*2):  
try:  
r1 = (k2*y+k2*k3*w-k3*k1*x)//(k2-k1*k3)  
p1 = (k3*w+y-x)//(k2-k1*k3)  
q1 = (k1*y-k1*x+k2*w)//(k2-k1*k3)  
w1, x1, y1 = q1 % p1, r1 % p1, r1 % q1  
if ((w1==w)&(x1==x)&(y1==y)):  
n1 = r1*p1*q1  
phi = (r1-1)*(p1-1)*(q1-1)  
d = pow(e,-1,phi)  
m = pow(c,d,n1)  
if (b'CSCTF' in long_to_bytes(m)):  
print(long_to_bytes(m))  
except:  
pass  
```
