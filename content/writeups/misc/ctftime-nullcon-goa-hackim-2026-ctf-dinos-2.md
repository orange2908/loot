---
title: "DiNoS - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "zone-walking", "nsec", "dnssec", "base64", "subprocess", "regex", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: misc/DiNoS"
source:
  name: "CTFtime writeup #40572"
  url: "https://ctftime.org/writeup/40572"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "DiNoS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** DiNoS
- **Author team:** 正规子群.AI
- **CTFtime tags:** misc, zone-walking, nsec, dnssec
- **CTFtime:** <https://ctftime.org/writeup/40572>

---
## 102 DiNoS

\- Category: `misc`  
\- Value: `50`  
\- Solves: `153`  
\- Solved by me: `True`  
\- Local directory: `misc/DiNoS`

### 题目描述  
> Some flag escaped its enclousure. Now it is mixed up with the herd([dinos.nullcon.net](http://dinos.nullcon.net)). Can you spot it?  
>  
> Verify you can visit the DiNoS: dig @ip -p 5052 TXT "[verify.enodns.nullcon.net](http://verify.enodns.nullcon.net)"  
>  
> Author: @vonDowntown

### 连接信息  
\- `52.59.124.14:5052`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# DiNoS

\---

## 题目信息  
\- Challenge: `DiNoS`  
\- 服务: `52.59.124.14:5052`  
\- 给定验证命令: `dig @ip -p 5052 TXT [verify.enodns.nullcon.net](http://verify.enodns.nullcon.net)`

\---

## 目标与初判  
题目提示 flag 混在 `[dinos.nullcon.net](http://dinos.nullcon.net)` 这群记录里，第一步先验证 DNS 服务可用性。

执行:  
```bash  
dig +tcp @52.59.124.14 -p 5052 TXT [verify.enodns.nullcon.net](http://verify.enodns.nullcon.net) +short  
```  
得到:  
```text  
"connection_successful_Have_Fun_With_our_DiNoS_Challenge"  
```

说明服务在线，但直接 UDP 查询会超时，需要走 TCP DNS。

\---

## 侦察过程

1\. 枚举基础记录:  
```bash  
dig +tcp @52.59.124.14 -p 5052 [dinos.nullcon.net](http://dinos.nullcon.net) SOA +noall +answer +authority  
dig +tcp @52.59.124.14 -p 5052 [dinos.nullcon.net](http://dinos.nullcon.net) NS +noall +answer  
```  
可确认存在权威区。

2\. 尝试区传输:  
```bash  
dig +tcp @52.59.124.14 -p 5052 [dinos.nullcon.net](http://dinos.nullcon.net) AXFR  
```  
结果 `Transfer failed`，不能直接 AXFR。

3\. 测试 DNSSEC 相关记录:  
```bash  
dig +tcp +dnssec @52.59.124.14 -p 5052 [dinos.nullcon.net](http://dinos.nullcon.net) NSEC +noall +answer +authority  
```  
发现返回了 `NSEC`，且包含 `next domain name`。这意味着可以做 NSEC zone walking：沿链表一个一个走，逐步恢复全部 owner name。

\---

## 利用思路

设区内 owner 集合按字典序为 $n_1, n_2, \dots, n_k$。NSEC 记录给出 $n_i \to n_{i+1}$（最后回到起点），因此可以线性恢复整个集合。

流程:  
1\. 从 `[dinos.nullcon.net](http://dinos.nullcon.net).` 开始取 `NSEC`。  
2\. 解析 next owner，继续查询下一个 `NSEC`。  
3\. 对每个 owner 查询 `TXT`。  
4\. 对 `TXT` 内容做多形态检测:  
\- 直接匹配 `ENO\\{...\\}`  
\- base64 解码后匹配  
\- 每隔一个字节有 `\x00` 的插零场景去交错后匹配

最终在遍历中命中 flag。

\---

## 失败/绕路记录  
\- 直接 `AXFR` 失败，无法一次性下载全区。  
\- 早期用 shell + `dig` 暴力遍历，速度慢且容易被远端断连。  
\- 改成带重试的脚本后稳定拿到结果。

\---

## 最终结果

```text  
ENO{RAAWR_RAAAAWR_You_found_me_hiding_among_some_NSEC_DiNoS}  
```

\---

## 复现方式

```bash  
python3 solution/[solution.py](http://solution.py)  
```

若网络抖动可加大步数:  
```bash  
python3 solution/[solution.py](http://solution.py) \--max-steps 30000  
```

#### 额外截图

### Exploit  
#### misc/DiNoS/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import argparse  
import base64  
import re  
import subprocess  
import sys  
import time

def run_dig(server: str, port: int, name: str, qtype: str, timeout_s: int = 3, tries: int = 1):  
cmd = [  
"dig", "+tcp", "+dnssec", f"+time={timeout_s}", f"+tries={tries}",  
f"@{server}", "-p", str(port), qtype, name, "+noall", "+answer", "+authority"  
]  
p = subprocess.run(cmd, capture_output=True, text=True)  
out = (p.stdout or "") + "\n" + (p.stderr or "")  
return [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.strip().startswith(";")]

def get_nsec_next(server: str, port: int, name: str, retry: int = 6):  
for i in range(retry):  
lines = run_dig(server, port, name, "NSEC")  
for ln in lines:  
parts = ln.split()  
if len(parts) >= 5 and parts[3] == "NSEC":  
return parts[0], parts[4]  
time.sleep(0.1 * (i + 1))  
return None, None

def get_txt_values(server: str, port: int, name: str, retry: int = 4):  
for i in range(retry):  
lines = run_dig(server, port, name, "TXT")  
vals = []  
for ln in lines:  
parts = ln.split()  
if len(parts) >= 5 and parts[3] == "TXT":  
matches = re.findall(r'"([^"]*)"', ln)  
if matches:  
vals.append("".join(matches))  
if vals:  
return vals  
time.sleep(0.05 * (i + 1))  
return []

def deinterleave_null(bs: bytes):  
if len(bs) < 4:  
return b""  
odd = bs[1::2]  
if odd and all(x == 0 for x in odd[: min(32, len(odd))]):  
return bs[::2]  
return b""

def candidate_strings(v: str):  
out = [v]  
b = v.encode(errors="ignore")  
di = deinterleave_null(b)  
if di:  
out.append(di.decode(errors="ignore"))  
if re.fullmatch(r"[A-Za-z0-9+/=]+", v):  
padded = v + "=" * ((4 - len(v) % 4) % 4)  
try:  
dec = base64.b64decode(padded, validate=False)  
out.append(dec.decode(errors="ignore"))  
di2 = deinterleave_null(dec)  
if di2:  
out.append(di2.decode(errors="ignore"))  
except Exception:  
pass  
return out

def solve(server: str, port: int, zone: str, max_steps: int = 10000):  
zone = zone if zone.endswith(".") else zone + "."  
cur = zone  
visited = {zone}  
flag_re = re.compile(r"ENO\\{[^}]+\\}")

for step in range(1, max_steps + 1):  
owner, nxt = get_nsec_next(server, port, cur)  
if not nxt:  
continue

for txt in get_txt_values(server, port, owner):  
for cand in candidate_strings(txt):  
m = flag_re.search(cand)  
if m:  
return m.group(0), owner, step

if nxt in visited:  
break  
visited.add(nxt)  
cur = nxt

return None, None, None

def main():  
parser = argparse.ArgumentParser()  
parser.add_argument("--server", default="52.59.124.14")  
parser.add_argument("--port", type=int, default=5052)  
parser.add_argument("--zone", default="[dinos.nullcon.net](http://dinos.nullcon.net)")  
parser.add_argument("--max-steps", type=int, default=20000)  
args = parser.parse_args()

flag, owner, step = solve(args.server, args.port, args.zone, args.max_steps)  
if not flag:  
print("[-] Flag not found")  
sys.exit(1)

print(f"[+] Flag found at step {step}")  
print(f"[+] Owner: {owner}")  
print(flag)

if __name__ == "__main__":  
main()  
```

\---
