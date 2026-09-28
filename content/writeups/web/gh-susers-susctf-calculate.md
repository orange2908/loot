---
title: "calculate - SUSCTF 2018"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "eval", "calculate", "web-exploitation", "susctf", "susers"]
summary: "web writeup for \"calculate\" from SUSCTF - techniques: eval, calculate, web-exploitation, susctf, susers."
source:
  name: "susers/Writeups"
  url: "https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/SUSCTF/Web/calculate/Writeup.md"
ctf:
  name: "SUSCTF"
  year: 2018
  challenge: "calculate"
---

## Source

- **CTF:** SUSCTF 2018
- **Challenge:** calculate
- **Repository:** [susers/Writeups](https://github.com/susers/Writeups)
- **File:** <https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/SUSCTF/Web/calculate/Writeup.md>

---
# Title
calculate
# Tools
* python
# exp
```python
import requests
import time 
from bs4 import BeautifulSoup as bs

sess=requests.session()
url="http://127.0.0.1:8089"
c=sess.get(url).content
b=bs(c,"lxml")
ans=""
for i in b.find_all('div'):
    ans=ans+i.text
res=eval(ans[:-1])
while True:
    try:
        time.sleep(1)
        c=sess.post(url,{"ans":res}).content
        b=bs(c,"lxml")
        ans=""
        for i in b.find_all('div'):
            ans=ans+i.text
        res=eval(ans[:-1])
    except:
        print c
        break
    
```
