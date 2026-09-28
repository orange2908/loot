---
title: "super express - MMACTF 2016"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "super", "express", "web-exploitation", "super-express", "mmactf"]
summary: "web writeup for \"super express\" from MMACTF - techniques: super, express, web-exploitation, super-express, mmactf."
source:
  name: "sixstars/ctf"
  url: "https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2016/MMACTF/super_express/README.md"
ctf:
  name: "MMACTF"
  year: 2016
  challenge: "super express"
---

## Source

- **CTF:** MMACTF 2016
- **Challenge:** super express
- **Repository:** [sixstars/ctf](https://github.com/sixstars/ctf)
- **File:** <https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2016/MMACTF/super_express/README.md>

---
```
>>> c='805eed80cbbccb94c36413275780ec94a857dfec8da8ca94a8c313a8ccf9'.decode('hex')
>>> be='TWCTF{'
>>> en=c[:6]
>>> for i in range(251):
	for j in range(251):
		found=True
		for k in range(6):
			if (ord(be[k])*i+j)%251!=ord(en[k]):
				found=False
		if found:
			print i,j

			
156 76
>>> ans=''
>>> for ch in c:
	for i in range(256):
		if (i*156+76)%251==ord(ch):
			ans+=chr(i)
			break

		
>>> ans
'TWCTF{Faster_Than_Shinkansen!}'
>>> 
```
