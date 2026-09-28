---
title: "Opalist - Nullcon Goa HackIM 2026 CTF"
category: "rev"
subcategory: "classical"
type: "writeup"
tags: ["rev", "base64", "reverse", "cipher", "substitution-cipher", "opalist", "classical", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- <https://ctf.nullcon.net/files/a0159eafc3c14537846ac35902744b7c/public.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4M30.aYqlMg.j7XVapLG0ph0xsJHGuyoNFY5lE>"
source:
  name: "CTFtime writeup #40559"
  url: "https://ctftime.org/writeup/40559"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Opalist"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Opalist
- **Author team:** 正规子群.AI
- **CTFtime tags:** base64, reverse, cipher
- **CTFtime:** <https://ctftime.org/writeup/40559>

---
## 108 Opalist

\- Category: `rev`  
\- Value: `50`  
\- Solves: `222`  
\- Solved by me: `True`  
\- Local directory: `N/A`

### 题目描述  
> We've got some weird output from a program written in a super obscure language. Can you help us recover the flag?  
>  
> HINT: To solve the challenge you have to use the following flag format: ENO{DECODED OUTPUT}  
>  
> Author: @gehaxelt

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/a0159eafc3c14537846ac35902744b7c/public.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4M30.aYqlMg.j7XVapLG0ph0xs_JHGuyoNFY5lE>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
The flag is:   
ENO{R3v_0p4L_4_FuN!}   
How it works:   
The OPAL program applies a 3-stage transformation to the input:  
1\. Substitution cipher (f1/f3) — each character's ASCII value is mapped through a lookup table   
2\. Shift cipher (f8) — computes a shift value based on the parity of each byte and its position, then adds that total shift to every byte mod 256  
3\. Base64 encode (f13) — standard base64 encoding of the resulting bytes  
To reverse from the output YnpYZVeGc45lc2VUZ05h:  
4\. Base64 decode → [98, 122, 88, 101, 87, 134, 115, 142, 101, 115, 101, 84, 103, 78, 97]  
5\. Brute-force the shift (S=27), verify it's self-consistent, subtract it from all bytes  
6\. Invert the substitution table to recover R3v_0p4L_4_FuN!  
The message "Rev opaL 4 Fun!" fits perfectly with the challenge theme — reversing a program written in the obscure OPAL language.

### Exploit  
\- Exploit 代码未在本地标准 `solution/` 目录找到，可能嵌在外部 WP 文本中。  
\- 已在上方 WP 小节插入相关文本来源，可继续抽取为独立脚本。

\---
