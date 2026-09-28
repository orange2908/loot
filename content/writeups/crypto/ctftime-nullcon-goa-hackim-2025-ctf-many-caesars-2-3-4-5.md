---
title: "many caesars - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "many", "caesars", "classical", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Inspecting [chall.py](<https://ctf.nullcon.net/files/c4ceafb8a9a0fc03840e413b2d6b69d1/chall.py?token=eyJ1c2VyX2lkIjoyNDAzLCJ0ZWFtX2lkIjo5MjIsImZpbGVfaWQiOjQ2fQ.Z6BsoQ.gJHm7oJzi66UJVjoMinh73Pq4qU>) and"
source:
  name: "CTFtime writeup #39859"
  url: "https://ctftime.org/writeup/39859"
original_source: "https://gopherhack.com/posts/nullcongoahackim2025ctf-many-caesars/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "many caesars"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** many caesars
- **Author team:** GopherHack
- **CTFtime:** <https://ctftime.org/writeup/39859>
- **Original writeup:** <https://gopherhack.com/posts/nullcongoahackim2025ctf-many-caesars/>

---
Inspecting [[chall.py](http://chall.py)](<https://ctf.nullcon.net/files/c4ceafb8a9a0fc03840e413b2d6b69d1/chall.py?token=eyJ1c2VyX2lkIjoyNDAzLCJ0ZWFtX2lkIjo5MjIsImZpbGVfaWQiOjQ2fQ.Z6BsoQ.gJHm7oJzi66UJVjoMinh73Pq4qU>) and running it with a custom `text.txt` and `flag.txt`, we see that every token (substring of lowercase characters separated by spaces) is Caesar shifted by an amount to produce [output.txt](<https://ctf.nullcon.net/files/4fedc0914e89798b8233bb383fe996c9/output.txt?token=eyJ1c2VyX2lkIjoyNDAzLCJ0ZWFtX2lkIjo5MjIsImZpbGVfaWQiOjQ3fQ.Z6BsoQ.e2SN4nDX8iDO-_KrF5bgAceRp54>). Specifically, the `count`th token is shifted by `chars.index(flag[count % len(flag)])` for all tokens. We annotate the code below.  
```py  
def caesar(msg, shift):  
return ''.join(chars[(chars.index(c) + shift) % len(chars)] for c in msg)

i = 0  
count = 0  
while i < len(text):  
if text[i] not in string.ascii_lowercase:  
print(text[i], end = '')  
i += 1  
else:  
# Get the next token  
j = i  
while text[j] in string.ascii_lowercase: j += 1

# Shift the token text[i:j]  
print(caesar(text[i:j], chars.index(flag[count % len(flag)])), end = '')  
count += 1  
i = j  
```

Since each token is Caesar ciphered, we can recover each token by checking all possible `len(chars) = 65` possible keys for each individual token and seeing which keys yields alphabetic English words.

For example, trying all shifts for the first token `AtvDxK` in [output.txt](<https://ctf.nullcon.net/files/4fedc0914e89798b8233bb383fe996c9/output.txt?token=eyJ1c2VyX2lkIjoyNDAzLCJ0ZWFtX2lkIjo5MjIsImZpbGVfaWQiOjQ3fQ.Z6BsoQ.e2SN4nDX8iDO-_KrF5bgAceRp54>) yields the alphabetic plaintext : key pairs  
```  
piksmz : l  
ohjrly : m  
ngiqkx : n  
mfhpjw : o  
legoiv : p  
kdfnhu : q  
jcemgt : r  
ibdlfs : s  
hacker : t  
```  
Clearly, the first word of the decrypted [output.txt](<https://ctf.nullcon.net/files/4fedc0914e89798b8233bb383fe996c9/output.txt?token=eyJ1c2VyX2lkIjoyNDAzLCJ0ZWFtX2lkIjo5MjIsImZpbGVfaWQiOjQ3fQ.Z6BsoQ.e2SN4nDX8iDO-_KrF5bgAceRp54>) is `hacker`, meaning the first character of the flag is `t`.

Running the following script to list the possible plaintext : key pairs and manually choosing the English words as well as corresponding keys yields the flag when concatenating all the keys together.  
```py  
import string

text = "AtvDxK lAopjz /i + vhw c6 uwnshnuqjx ymfy kymhi Kyv 47+3l/eh Bs kpfkxkfwcnu Als 9phdgj9 +ka ymzuBGxmFq 6fdglk8i CICDowC, sjxir bjme+pfwfkd 6li=fj=kp, nCplEtGtEJ, lyo qeb INKLNBM vm ademb7697. ollqba lq DitCmA xzhm fx ef7dd7ii, wIvv eggiww GB kphqtocvkqp, 3d6 MAx ilsplm /d rpfkd vnloov hc nruwtAj xDxyjrx vexliv KyrE +3hc Gurz, jcemgt ixlmgw 9f7gmj5/9k obpmlkpf/ib mzp 8k/=64c ECo sj qb=eklildv. =k loGznlEpD qzC qo+kpm+obk=v, vHEEtuHKtMBHG, huk h7if75j/d9 mofs+=v, zkloh lqAkwCzioqvo rfqnhntzx fhynAnynjx b/a7 JKvrCzEx hexe BE ecwukpi 63c397. MAxLx wypujpwslz 3/c ql irvwhu 9bbcj1h9cb fsi f tswmxmzi zDGrtK ed FBpvrGL vjtqwij ixlmgep 5f8 =lkpqor=qfsb tmowuzs."

chars = string.ascii_letters + string.digits + '+/='

def caesar(msg, shift):  
return ''.join(chars[(chars.index(c) - shift) % len(chars)] for c in msg)

i = 0  
count = 0  
while i < len(text):  
if text[i] not in chars:  
i += 1  
else:  
j = i  
while j < len(text) and text[j] in chars: j += 1  
for k in range(len(chars)):  
word = caesar(text[i:j], k)  
if word.isalpha() and word.islower():  
print(word, ":", chars[k])  
print()  
count += 1  
i = j  
```

Flag: `ENO{th3_d1ffer3nce5_m4ke_4ll_th3_diff3renc3}`
