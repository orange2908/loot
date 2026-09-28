---
title: "judge - SUSCTF 2019"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "eval", "judge", "web-exploitation", "susctf", "susers"]
summary: "web writeup for \"judge\" from SUSCTF - techniques: eval, judge, web-exploitation, susctf, susers."
source:
  name: "susers/Writeups"
  url: "https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2019/SUSCTF/web/judge/Writeup.md"
ctf:
  name: "SUSCTF"
  year: 2019
  challenge: "judge"
---

## Source

- **CTF:** SUSCTF 2019
- **Challenge:** judge
- **Repository:** [susers/Writeups](https://github.com/susers/Writeups)
- **File:** <https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2019/SUSCTF/web/judge/Writeup.md>

---
# Title
judge
# Tools
* python
# exp
```python
import requests
from lxml import etree
import time

url = "http://211.65.197.117:15000/"
session = requests.Session()


while True:
    response = session.get(url).text
    calc = etree.HTML(response).xpath("//form/div/text()")
    s=calc[0]
    s=s.split('=')
    s[0]=eval(s[0])
    s[1]=eval(s[1])
    result=(s[0]==s[1])
    if(result):
        result="true"
    else :
        result="false"
    print(result)
    data = {
        "answer": result
    }
    time.sleep(1)

    print(data)
    req = session.post(url, data=data)
    print(req.text)
```
