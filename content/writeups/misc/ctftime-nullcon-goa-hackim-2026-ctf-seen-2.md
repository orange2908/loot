---
title: "Seen - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["html", "misc", "source-inspection", "seen", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- <https://ctf.nullcon.net/files/0a38f4205f7b2aa49f2a796886f90c9b/index.html?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4OH0.aYqlNQ.mjT-bR8eW463Z8rnntzCI0hRTGA>"
source:
  name: "CTFtime writeup #40570"
  url: "https://ctftime.org/writeup/40570"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Seen"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Seen
- **Author team:** 正规子群.AI
- **CTFtime tags:** html, misc, source-inspection
- **CTFtime:** <https://ctftime.org/writeup/40570>

---
## 116 Seen

\- Category: `misc`  
\- Value: `50`  
\- Solves: `327`  
\- Solved by me: `True`  
\- Local directory: `N/A`

### 题目描述  
> Well this LOOKS like its an easy one :)

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/0a38f4205f7b2aa49f2a796886f90c9b/index.html?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4OH0.aYqlNQ.mjT-bR8eW463Z8rnntzCI0hRTGA>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP

### Exploit  
\- Exploit 代码未在本地标准 `solution/` 目录找到，可能嵌在外部 WP 文本中。  
\- 已在上方 WP 小节插入相关文本来源，可继续抽取为独立脚本。

\---

## Additional Reproduction Notes

This task is a hidden-content challenge. The rendered view intentionally hides the token, but the source still contains it.

### Steps

1\. Open the provided `index.html`.  
2\. Use browser developer tools (`View Source` / `Inspect Element`).  
3\. Search for `ENO{` in HTML nodes/comments/hidden blocks.  
4\. Copy the discovered token and submit.

### Minimal extractor

```python  
import re  
from bs4 import BeautifulSoup  
html=open('index.html','r',encoding='utf-8',errors='ignore').read()  
soup=BeautifulSoup(html,'html.parser')  
raw='\n'.join([html, soup.get_text('\n')])  
for m in re.findall(r'ENO\\{[^}]+\\}', raw):  
print(m)  
```
