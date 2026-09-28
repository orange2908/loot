---
title: "Booking Key - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "static-analysis"
type: "writeup"
tags: ["crypto", "state-machine", "radare2", "eval", "wayback", "static-analysis", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: cry/booking"
source:
  name: "CTFtime writeup #40561"
  url: "https://ctftime.org/writeup/40561"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Booking Key"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Booking Key
- **Author team:** 正规子群.AI
- **CTFtime tags:** crypto, state-machine
- **CTFtime:** <https://ctftime.org/writeup/40561>

---
## 96 Booking Key

\- Category: `cry`  
\- Value: `113`  
\- Solves: `130`  
\- Solved by me: `True`  
\- Local directory: `cry/booking`

### 题目描述  
> Books have always been a beautiful place to hide information, sometimes in plain sight.

### 连接信息  
\- `52.59.124.14:5102`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/1156ede7e1487f7638dbb38c3e89d219/chall.py?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo3Nn0.aYqlPA._c1zPZx0ADuWwyRKC3gOppNlLJQ>`  
\- `<https://ctf.nullcon.net/files/01659956f053828a8064fa41fa585c24/book.txt?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjoxMDN9.aYqlPA.Xs4z-dmV-iovcnXElGqy3y5X1ck>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Nullcon 2026 Booking Key

\---

## 题目信息

\- 远程地址: `52.59.124.14:5102`  
\- 已知附件: `task/[chal.py](http://chal.py)`  
\- 目标: 连续 3 轮恢复 32 字节随机密码，服务端最后返回 flag

\---

## 附件代码分析

核心逻辑在 `encrypt(message, book, start)`:

```python  
for char in message:  
count = 0  
while book[current] != char:  
current = (current + 1) % len(book)  
count += 1  
cipher.append(count)  
```

主流程每轮会：

1\. 随机 `key` 作为起点 `start`  
2\. 生成 32 长度密码 `password`，字符来自 `BOOK` 中出现过的英文字母  
3\. 输出 `cipher`（长度 32 的整数数组）  
4\. 要求我们输入原始 `password`

连续 3 轮全部正确后输出 flag。

\---

## 数学建模

记 `BOOK` 长度为 $N$，第 $i$ 轮字符为 $p_i$，游标状态为 $s_i$：

\- 初始 $s_0 = start$  
\- 对每个字符 $p_i$，定义  
$$  
s_i = \operatorname{nextPos}(p_i, s_{i-1})  
$$  
这里 `nextPos` 表示从位置 $s_{i-1}$ 开始（包含当前位）沿环向前遇到字符 $p_i$ 的首个位置。  
\- 输出密文分量为  
$$  
c_i = (s_i - s_{i-1}) \bmod N  
$$  
且 $c_i \in [0, N-1]$。

关键点：一旦 `BOOK` 已知，给定 $c_i$ 与候选起点 $s_{i-1}$，当前位置字符必须满足 `BOOK[(s_{i-1}+c_i) % N]`。再用“下一个同字符出现位置”的距离校验可排除伪解。

\---

## 求解算法

对每一条 `cipher`：

1\. 枚举 `start` 从 `0` 到 `N-1`  
2\. 按上式逐位恢复候选字符，生成 32 长字符串  
3\. 用“下一个同字符出现位置距离 = c_i”做严格一致性检查  
4\. 保留唯一解；若非唯一或无解，则该连接放弃重连

单轮复杂度约为 $O(N \cdot 32)$。

\---

## 关键坑点与失败尝试

### 1. `book.txt` 不在本地附件中

只有 `[chal.py](http://chal.py)`，没有 `book.txt`。题面文本明显对应《Alice's Adventures in Wonderland》某个 Gutenberg 版本，但不同镜像的头尾、空行、换行宽度都不完全一致。

### 2. 文本版本差异会直接导致不可解

我分别尝试了：

\- Gutenberg 新版 `19033.txt.utf-8`  
\- Archive 的旧版 `19033.txt`  
\- 多种裁剪区间（从 `Produced by ...` 开始、从插图开始、到最后插图结束等）

现象：部分连接可解，部分连接不可解，说明远端可能存在实例差异或文本版本不一致。

### 3. 交互细节坑

早期脚本使用文件句柄写入后未 `flush`，导致服务端一直等待输入，表现为超时。修复 `flush` 后可稳定进入下一轮。

### 4. 单线程命中率低

单连接常出现 `r1` 可过但 `r2/r3` 不可解。最终改为并发重连，显著缩短拿到 3 轮全过的时间。

\---

## 内存布局与状态布局

虽然这是密码学/编码恢复题，不是传统 pwn，但仍可从运行态描述其内存结构：

1\. 服务端 `BOOK`  
\- Python `str` 对象，存放完整书本文本（堆上不可变对象）  
\- `current` 是指向索引的整型状态，按环形递增

2\. 每轮生成态  
\- `password`: 长度 32 的 `str`  
\- `cipher`: 长度 32 的 `list[int]`  
\- `count`: 每个字符局部计数器

3\. 解题脚本索引结构  
\- `positions: dict[char, list[int]]`，每个字母对应升序位置表  
\- 枚举 `start` 时仅维护少量局部变量（`cur`, `idx`, `nxt`, `out`），空间开销主要在 `BOOK` 与 `positions`

4\. 逻辑上的“环形内存”  
\- `current = (current + 1) % N` 等价于在长度 $N$ 的环形缓冲区上移动游标  
\- `cipher[i]` 本质是两次状态之间的环形距离

\---

## 最终利用策略

`solution/[solution.py](http://solution.py)` 采用如下策略：

1\. 自动下载多个 `Alice` 文本来源  
2\. 生成多个候选 `BOOK` 变体（不同裁剪方式）  
3\. 对每条 `cipher` 在全部候选上尝试唯一解恢复  
4\. 多线程并发重连远端，直到同一连接 3 轮都恢复成功  
5\. 自动提取 flag

\---

## 运行方式

```bash  
python3 solution/[solution.py](http://solution.py) \--host 52.59.124.14 --port 5102 --threads 8 --max-attempts 2000  
```

成功时会打印：

```text  
[+] FLAG: ENO{y0u_f1nd_m4ny_th1ng5_in_w0nd3r1and}  
```

\---

## Flag

```text  
ENO{y0u_f1nd_m4ny_th1ng5_in_w0nd3r1and}  
```

### Exploit  
#### cry/booking/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import argparse  
import ast  
import bisect  
import re  
import socket  
import string  
import threading  
import time  
import urllib.request  
from typing import Dict, List, Optional, Tuple

CANDIDATE_URLS = [  
"<https://archive.org/download/alicesadventures19033gut/19033.txt>",  
"<https://www.gutenberg.org/ebooks/19033.txt.utf-8>",  
]

KEY_MARKERS = {  
"produced": "Produced by Jason Isbell",  
"illustration": "[Illustration: Alice in the Room of the Duchess.]",  
"title": "ALICE'S ADVENTURES IN WONDERLAND",  
"last_illus": "[Illustration]",  
}

LETTERS = set(string.ascii_letters)

class BookModel:  
def __init__(self, name: str, book: str):  
[self.name](http://self.name) = name  
self.book = book  
self.n = len(book)  
self.positions: Dict[str, List[int]] = {}  
for i, ch in enumerate(book):  
if ch in LETTERS:  
self.positions.setdefault(ch, []).append(i)

def decode_unique(self, cipher: List[int]) -> Optional[str]:  
solution = None  
for start in range(self.n):  
cur = start  
out = []  
ok = True  
for d in cipher:  
idx = (cur + d) % self.n  
ch = self.book[idx]  
if ch not in LETTERS:  
ok = False  
break

arr = self.positions[ch]  
k = bisect.bisect_left(arr, cur)  
nxt = arr[k] if k < len(arr) else arr[0] + self.n  
if nxt - cur != d:  
ok = False  
break

out.append(ch)  
cur = idx

if ok:  
pw = "".join(out)  
if solution is None:  
solution = pw  
elif solution != pw:  
return None  
return solution

def fetch_text(url: str, timeout: int = 20) -> str:  
with urllib.request.urlopen(url, timeout=timeout) as resp:  
data = resp.read()  
text = data.decode("utf-8", errors="replace")  
return text.replace("\r\n", "\n").replace("\r", "\n")

def build_variants(base_name: str, text: str) -> List[Tuple[str, str]]:  
variants = [(f"{base_name}:full", text)]

p = text.find(KEY_MARKERS["produced"])  
i = text.find(KEY_MARKERS["illustration"])  
t = text.find(KEY_MARKERS["title"])  
li = text.rfind(KEY_MARKERS["last_illus"])

if p != -1:  
variants.append((f"{base_name}:from_produced", text[p:]))  
if i != -1:  
variants.append((f"{base_name}:from_illustration", text[i:]))  
if t != -1:  
variants.append((f"{base_name}:from_title", text[t:]))  
if p != -1 and li != -1 and li > p:  
variants.append((f"{base_name}:produced_to_last_illus", text[p : li + len(KEY_MARKERS["last_illus"])]))

# 补一版去掉多余连续空行，兼容部分镜像格式差异  
compact = re.sub(r"\n{3,}", "\n\n", text)  
variants.append((f"{base_name}:compact_blank", compact))

out = []  
seen = set()  
for name, v in variants:  
if not v:  
continue  
if v in seen:  
continue  
seen.add(v)  
out.append((name, v))  
return out

def load_book_models() -> List[BookModel]:  
models = []  
seen = set()  
for url in CANDIDATE_URLS:  
text = fetch_text(url)  
base_name = url.rsplit("/", 1)[-1]  
for name, variant in build_variants(base_name, text):  
if variant in seen:  
continue  
seen.add(variant)  
models.append(BookModel(name, variant))  
return models

def parse_cipher_line(line: str) -> List[int]:  
return ast.literal_eval(line.strip())

def decode_password(models: List[BookModel], cipher: List[int]) -> Optional[str]:  
cands = set()  
for m in models:  
pw = m.decode_unique(cipher)  
if pw is not None:  
cands.add(pw)  
if len(cands) == 1:  
return next(iter(cands))  
return None

def attempt_once(host: str, port: int, models: List[BookModel], timeout_sec: int) -> Tuple[bool, str]:  
s = None  
try:  
s = socket.create_connection((host, port), timeout=timeout_sec)  
s.settimeout(timeout_sec)  
f = s.makefile("rw", encoding="utf-8", newline="\n")

banner = f.readline()  
if not banner:  
return False, "no_banner"

for _ in range(3):  
line = f.readline()  
if not line:  
return False, "no_cipher"  
cipher = parse_cipher_line(line)  
pw = decode_password(models, cipher)  
if pw is None:  
return False, "unsolved"

f.write(pw + "\n")  
f.flush()  
resp = f.readline()  
if not resp or "correct" not in resp:  
return False, "wrong_or_closed"

tail = f.read() or ""  
m = re.search(r"[A-Za-z0-9_]+\\{[^\n\r}]*\\}", tail)  
if m:  
return True, m.group(0)  
return True, tail.strip() or "success_without_flag"  
except Exception as e:  
return False, f"exception:{e}"  
finally:  
if s is not None:  
try:  
s.close()  
except Exception:  
pass

def main() -> None:  
parser = argparse.ArgumentParser()  
parser.add_argument("--host", default="52.59.124.14")  
parser.add_argument("--port", type=int, default=5102)  
parser.add_argument("--threads", type=int, default=8)  
parser.add_argument("--timeout", type=int, default=8)  
parser.add_argument("--max-attempts", type=int, default=2000)  
args = parser.parse_args()

print("[+] Loading candidate books...")  
models = load_book_models()  
print(f"[+] Loaded {len(models)} book variants")

stop = threading.Event()  
lock = threading.Lock()  
stats = {  
"attempts": 0,  
"unsolved": 0,  
"success_round3": 0,  
"other_fail": 0,  
}  
answer = {"flag": None}

def worker() -> None:  
while not stop.is_set():  
with lock:  
if stats["attempts"] >= args.max_attempts:  
return  
stats["attempts"] += 1  
ok, info = attempt_once(args.host, args.port, models, args.timeout)  
with lock:  
if ok:  
stats["success_round3"] += 1  
answer["flag"] = info  
stop.set()  
return  
if info == "unsolved":  
stats["unsolved"] += 1  
else:  
stats["other_fail"] += 1

threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.threads)]  
for th in threads:  
th.start()

last = 0.0  
while any(th.is_alive() for th in threads):  
if stop.is_set():  
break  
now = time.time()  
if now - last >= 2:  
with lock:  
print(  
f"[*] attempts={stats['attempts']} unsolved={stats['unsolved']} "  
f"other_fail={stats['other_fail']}"  
)  
last = now  
time.sleep(0.2)

for th in threads:  
th.join(timeout=0.2)

if answer["flag"] is not None:  
print("[+] FLAG:", answer["flag"])  
else:  
with lock:  
print(  
f"[-] Not found within attempts={stats['attempts']}, "  
f"unsolved={stats['unsolved']}, other_fail={stats['other_fail']}"  
)

if __name__ == "__main__":  
main()  
```

\---
