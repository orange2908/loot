---
title: "many caesars - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "regex", "many", "caesars", "classical", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "I took an old cipher and modified it to make it secure again."
source:
  name: "CTFtime writeup #39966"
  url: "https://ctftime.org/writeup/39966"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "many caesars"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** many caesars
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39966>

---
# many caesers

## Description

I took an old cipher and modified it to make it secure again. By breaking the regular patterns I made sure the known attacks don't work. Now I can use it to encrypt texts with my favourite Chat partner.

## Source

\- `[chall.py](http://chall.py)`  
```  
import string  
import re

text = open('text.txt','r').read().lower()  
flag = open('flag.txt','r').read().strip()[4:-1].replace('_','+')  
chars = string.ascii_letters + string.digits + '+/='  
regex = re.compile('[' + chars + ']{5,70}')  
assert re.fullmatch(regex, flag)

def caesar(msg, shift):  
return ''.join(chars[(chars.index(c) + shift) % len(chars)] for c in msg)

i = 0  
count = 0  
while i < len(text):  
if text[i] not in string.ascii_lowercase:  
print(text[i], end = '')  
i += 1  
else:  
j = i  
while text[j] in string.ascii_lowercase: j += 1  
print(caesar(text[i:j], chars.index(flag[count % len(flag)])), end = '')  
count += 1  
i = j

```

\- `output.txt`  
```  
AtvDxK lAopjz /i + vhw c6 uwnshnuqjx ymfy kymhi Kyv 47+3l/eh Bs kpfkxkfwcnu Als 9phdgj9 +ka ymzuBGxmFq 6fdglk8i CICDowC, sjxir bjme+pfwfkd 6li=fj=kp, nCplEtGtEJ, lyo qeb INKLNBM vm ademb7697. ollqba lq DitCmA xzhm fx ef7dd7ii, wIvv eggiww GB kphqtocvkqp, 3d6 MAx ilsplm /d rpfkd vnloov hc nruwtAj xDxyjrx vexliv KyrE +3hc Gurz, jcemgt ixlmgw 9f7gmj5/9k obpmlkpf/ib mzp 8k/=64c ECo sj qb=eklildv. =k loGznlEpD qzC qo+kpm+obk=v, vHEEtuHKtMBHG, huk h7if75j/d9 mofs+=v, zkloh lqAkwCzioqvo rfqnhntzx fhynAnynjx b/a7 JKvrCzEx hexe BE ecwukpi 63c397. MAxLx wypujpwslz 3/c ql irvwhu 9bbcj1h9cb fsi f tswmxmzi zDGrtK ed FBpvrGL vjtqwij ixlmgep 5f8 =lkpqor=qfsb tmowuzs.  
```

## Solution  
\- Starting with empty string , in each iteration I add one character to the flag from the charset and check what the decrypted message would be if this were the flag.  
\- If that corresponding plaintext for that particular character reveals an extra correct word, I accepted that as the next character of the flag  
\- To get the plaintext from the ciphertext, I simply changed the shift in the encrypt function to subtract

\- `[solve.py](http://solve.py)`  
```  
import string

text = "AtvDxK lAopjz /i + vhw c6 uwnshnuqjx ymfy kymhi Kyv 47+3l/eh Bs kpfkxkfwcnu Als 9phdgj9 +ka ymzuBGxmFq 6fdglk8i CICDowC, sjxir bjme+pfwfkd 6li=fj=kp, nCplEtGtEJ, lyo qeb INKLNBM vm ademb7697. ollqba lq DitCmA xzhm fx ef7dd7ii, wIvv eggiww GB kphqtocvkqp, 3d6 MAx ilsplm /d rpfkd vnloov hc nruwtAj xDxyjrx vexliv KyrE +3hc Gurz, jcemgt ixlmgw 9f7gmj5/9k obpmlkpf/ib mzp 8k/=64c ECo sj qb=eklildv. =k loGznlEpD qzC qo+kpm+obk=v, vHEEtuHKtMBHG, huk h7if75j/d9 mofs+=v, zkloh lqAkwCzioqvo rfqnhntzx fhynAnynjx b/a7 JKvrCzEx hexe BE ecwukpi 63c397. MAxLx wypujpwslz 3/c ql irvwhu 9bbcj1h9cb fsi f tswmxmzi zDGrtK ed FBpvrGL vjtqwij ixlmgep 5f8 =lkpqor=qfsb tmowuzs."

chars = string.ascii_letters + string.digits + '+/='  
print(chars)

def caesar(msg, shift):  
return ''.join(chars[(chars.index(c) - shift) % len(chars)] for c in msg)

flag_ = 'th3+d1ffer3nce5+m4ke+4ll+th3+diff3renc3th'  
for a in chars:  
flag = flag_+a  
print(flag)  
i = 0  
count = 0  
while i < len(text):  
if text[i] not in chars:  
print(text[i], end = '')  
i += 1  
else:  
j = i  
while text[j] in chars: j += 1  
print(caesar(text[i:j], chars.index(flag[count % len(flag)])), end = '')  
count += 1  
i = j  
print()  
```

\- command : `python3 [solve.py](http://solve.py) > dump`

# Flag  
`ENO{th3_d1ffer3nce5_m4ke_4ll_th3_diff3renc3}`
