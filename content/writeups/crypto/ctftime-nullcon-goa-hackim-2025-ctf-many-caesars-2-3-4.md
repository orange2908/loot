---
title: "many caesars - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "many", "caesars", "classical", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "some automated bruteforce with manual"
source:
  name: "CTFtime writeup #39893"
  url: "https://ctftime.org/writeup/39893"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "many caesars"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** many caesars
- **Author team:** thehackerscrew
- **CTFtime tags:** caesar
- **CTFtime:** <https://ctftime.org/writeup/39893>

---
some automated bruteforce with manual

```py  
import string  
import re

text = "AtvDxK lAopjz /i + vhw c6 uwnshnuqjx ymfy kymhi Kyv 47+3l/eh Bs kpfkxkfwcnu Als 9phdgj9 +ka ymzuBGxmFq 6fdglk8i CICDowC, sjxir bjme+pfwfkd 6li=fj=kp, nCplEtGtEJ, lyo qeb INKLNBM vm ademb7697. ollqba lq DitCmA xzhm fx ef7dd7ii, wIvv eggiww GB kphqtocvkqp, 3d6 MAx ilsplm /d rpfkd vnloov hc nruwtAj xDxyjrx vexliv KyrE +3hc Gurz, jcemgt ixlmgw 9f7gmj5/9k obpmlkpf/ib mzp 8k/=64c ECo sj qb=eklildv. =k loGznlEpD qzC qo+kpm+obk=v, vHEEtuHKtMBHG, huk h7if75j/d9 mofs+=v, zkloh lqAkwCzioqvo rfqnhntzx fhynAnynjx b/a7 JKvrCzEx hexe BE ecwukpi 63c397. MAxLx wypujpwslz 3/c ql irvwhu 9bbcj1h9cb fsi f tswmxmzi zDGrtK ed FBpvrGL vjtqwij ixlmgep 5f8 =lkpqor=qfsb tmowuzs."  
chars = string.ascii_letters + string.digits + "+/="  
regex = re.compile("[" + chars + "]{5,70}")

def caesar(msg, shift):  
# return "".join(chars[(chars.index(c) + shift) % len(chars)] for c in msg)  
res = ""  
for i in msg:  
if i in chars:  
res += chars[(chars.index(i) + shift) % len(chars)]  
else:  
res += i  
return res

words = []  
i = 0  
count = 0  
while i < len(text):  
if text[i] not in chars:  
i += 1  
else:  
j = i  
while text[j] in chars:  
j += 1  
words.append(text[i:j])  
i = j  
"""

for p in range(len(words)):  
print(p)  
key = chars.index("t")  
a = caesar(words[p],-key)  
print(a)  
key = chars.index("h")  
a = caesar(words[p], -key)  
print(a)  
"""  
for p in range(0,39):  
print(f"p = {p}")  
s = ""  
for q in range(p,len(words),39):  
s += words[q] + " "  
print(s)  
for x in range(len(chars)):  
a = caesar(s, -x)  
ok = True  
for b in a:  
if b not in string.ascii_lowercase + " ":  
ok = False  
if ok:  
print(chars[x], a)  
```
