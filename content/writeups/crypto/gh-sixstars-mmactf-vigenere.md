---
title: "vigenere - MMACTF 2016"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "vigenere", "base64", "classical", "cryptography", "mmactf"]
summary: "From the distance of repeated 3-grams we can guess key length is 12."
source:
  name: "sixstars/ctf"
  url: "https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2016/MMACTF/vigenere/README.md"
ctf:
  name: "MMACTF"
  year: 2016
  challenge: "vigenere"
---

## Source

- **CTF:** MMACTF 2016
- **Challenge:** vigenere
- **Repository:** [sixstars/ctf](https://github.com/sixstars/ctf)
- **File:** <https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2016/MMACTF/vigenere/README.md>

---
From the distance of repeated 3-grams we can guess key length is `12`. Then using brute force byte by byte.

```
for ch in chars:
	ok=True
	kl=12
	for i in range(len(c)/kl+1):
		pos=i*kl
		if pos>=len(c):
			continue
		res=shift(c[pos],ch)
		aa=nch.index(res)
		if aa&32!=0:
			ok=False
			#print 'failed at',i
			break
	if ok:
		print ch,
```

```
for ch in chars:
	kpre2='shA6'
	kpre1='I8HU'
	kpre='XLF'
	kl=12
	ok=True
	tt=[]
	for i in range(len(c)/kl+1):
		pos=i*kl+8
		if pos+4>=len(c):
			continue
		res=shift(c[pos-8],kpre2[0])+shift(c[pos-7],kpre2[1])+shift(c[pos-6],kpre2[2])+shift(c[pos-5],kpre2[3])
		t2=res.decode('base64')
		res=shift(c[pos-4],kpre1[0])+shift(c[pos-3],kpre1[1])+shift(c[pos-2],kpre1[2])+shift(c[pos-1],kpre1[3])
		t1=res.decode('base64')
		res=shift(c[pos],kpre[0])+shift(c[pos+1],kpre[1])+shift(c[pos+2],kpre[2])+shift(c[pos+3],ch)
		t=res.decode('base64')
		for cch in t:
			if cch not in string.printable:
				ok=False
		if not ok:
			break
		tt.append(t2+t1+t)
	if ok:
		print ch
		print tt
```

Final key is `shA6I8HUXLFY` and message `SKK is a Japanese Input Method developed by Sato Masahiko. Original SKK targets Emacs. However, there are various SKK programs that works other systems such as SKKFEP(for Windows), AquaSKK(for MacOS X) and eskk(for vim).\nOK, the flag is TWCTF{C14ss1caL CiPhEr iS v3ry fun}.\n`
