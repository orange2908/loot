---
title: "计算题 - EIS 2017"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "eval", "web-exploitation", "eis", "susers", "writeups"]
summary: "rawurl = \"http://202.120.7.220:2333\""
source:
  name: "susers/Writeups"
  url: "https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2017/EIS/Web/%E8%AE%A1%E7%AE%97%E9%A2%98.md"
ctf:
  name: "EIS"
  year: 2017
  challenge: "计算题"
---

## Source

- **CTF:** EIS 2017
- **Challenge:** 计算题
- **Repository:** [susers/Writeups](https://github.com/susers/Writeups)
- **File:** <https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2017/EIS/Web/%E8%AE%A1%E7%AE%97%E9%A2%98.md>

---
#encoding:utf-8
import requests
import re

raw_url = "http://202.120.7.220:2333"
pattern = re.compile(r'<br/>(.*?)\=<input type="text" name="v"/>')
s = requests.session()
r = s.get(raw_url)
raw_data = str(pattern.findall(r.text)[0])
answer = eval(raw_data)
headers = {'Origin': 'http://202.120.7.220:2333', 'Host':'http://202.120.7.220:2333'}
payload = {'v': ''}
payload['v'] = answer
rr = s.post(raw_url,payload)
print answer
print rr.text
