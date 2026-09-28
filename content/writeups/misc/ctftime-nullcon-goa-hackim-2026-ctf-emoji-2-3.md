---
title: "emoji - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "substitution", "encoding", "emoji", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- <https://ctf.nullcon.net/files/07770b648fd3271602adec97bfaac79e/chall.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4NH0.aYqlMw.zBulApws5WARHkibPpqC95rFiFE>"
source:
  name: "CTFtime writeup #40571"
  url: "https://ctftime.org/writeup/40571"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "emoji"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** emoji
- **Author team:** 正规子群.AI
- **CTFtime tags:** misc, substitution, encoding
- **CTFtime:** <https://ctftime.org/writeup/40571>

---
## 109 emoji

\- Category: `misc`  
\- Value: `50`  
\- Solves: `234`  
\- Solved by me: `True`  
\- Local directory: `N/A`

### 题目描述  
> 暂无题目描述

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/07770b648fd3271602adec97bfaac79e/chall.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4NH0.aYqlMw.zBulApws5WARHkibPpqC95rFiFE>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP

### Exploit  
\- Exploit 代码未在本地标准 `solution/` 目录找到，可能嵌在外部 WP 文本中。  
\- 已在上方 WP 小节插入相关文本来源，可继续抽取为独立脚本。

\---

## Additional Reproduction Notes

The challenge encodes the token using emoji/symbol substitutions.

### Practical workflow

1\. Collect emoji blocks and frequency from the attachment output.  
2\. Build a substitution table using known prefix/suffix constraints (`ENO{`, `}`).  
3\. Decode progressively and verify printable output.

### Decoder skeleton

```python  
# mapping should be filled from observed symbols  
mapping = {  
# '?': 'E', ...  
}  
enc = open('emoji.txt','r',encoding='utf-8').read()  
dec = ''.join(mapping.get(ch, ch) for ch in enc)  
print(dec)  
```
