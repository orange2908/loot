---
title: "many caesars - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "many", "caesars", "classical", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We can bruteforce shift of each word (separated by , , and .) then choose the most meaningful words for each word."
source:
  name: "CTFtime writeup #39928"
  url: "https://ctftime.org/writeup/39928"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#many-caesars"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "many caesars"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** many caesars
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39928>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#many-caesars>

---
We can bruteforce shift of each word (separated by `_`, `,` and `.`) then choose the most meaningful words for each word. The corresponding shift of each word reveal part of the flag.  
```python  
import string

def caesar(msg, shift):  
return ''.join(chars[(chars.index(c) - shift) % len(chars)] for c in msg)

chars = string.ascii_letters + string.digits + '+/='  
ct = "AtvDxK lAopjz /i + vhw c6 uwnshnuqjx ymfy kymhi Kyv 47+3l/eh Bs kpfkxkfwcnu Als 9phdgj9 +ka ymzuBGxmFq 6fdglk8i CICDowC, sjxir bjme+pfwfkd 6li=fj=kp, nCplEtGtEJ, lyo qeb INKLNBM vm ademb7697. ollqba lq DitCmA xzhm fx ef7dd7ii, wIvv eggiww GB kphqtocvkqp, 3d6 MAx ilsplm /d rpfkd vnloov hc nruwtAj xDxyjrx vexliv KyrE +3hc Gurz, jcemgt ixlmgw 9f7gmj5/9k obpmlkpf/ib mzp 8k/=64c ECo sj qb=eklildv. =k loGznlEpD qzC qo+kpm+obk=v, vHEEtuHKtMBHG, huk h7if75j/d9 mofs+=v, zkloh lqAkwCzioqvo rfqnhntzx fhynAnynjx b/a7 JKvrCzEx hexe BE ecwukpi 63c397. MAxLx wypujpwslz 3/c ql irvwhu 9bbcj1h9cb fsi f tswmxmzi zDGrtK ed FBpvrGL vjtqwij ixlmgep 5f8 =lkpqor=qfsb tmowuzs."  
ct = ct.replace(' ', ']').replace(',', ']').replace('.', ']')

ct = ct.split(']')  
ct = [x for x in ct if x != '']

for block in ct:  
for i in range(len(chars)):  
val = caesar(block, i)  
if any(x not in string.ascii_lowercase for x in val[1:]):  
continue  
if val[0] not in string.ascii_letters:  
continue  
print(val, chars[i])  
print()  
  
# th3_d1ffer3nce5_m4ke_4ll_th3_diff3renc3  
```
