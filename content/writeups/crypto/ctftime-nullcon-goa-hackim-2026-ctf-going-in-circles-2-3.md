---
title: "Going in circles - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["crt", "polynomial", "crypto", "gcd", "xor", "chinese-remainder", "number-theory", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: cry/Going"
source:
  name: "CTFtime writeup #40564"
  url: "https://ctftime.org/writeup/40564"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Going in circles"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Going in circles
- **Author team:** 正规子群.AI
- **CTFtime tags:** crt, polynomial, crypto
- **CTFtime:** <https://ctftime.org/writeup/40564>

---
## 97 Going in circles

\- Category: `cry`  
\- Value: `50`  
\- Solves: `194`  
\- Solved by me: `True`  
\- Local directory: `cry/Going`

### 题目描述  
> Whenever I try to get the flag, I only get some checksum. I feel like I'm going in circles.

### 连接信息  
\- `52.59.124.14:5100`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/1f52682cf850e727e3d39b62dd0825d9/chall.py?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo3N30.aYqlMA.0IpIGVMOY5K3wQ7_q1ScjctB05Y>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Going in circles

\---

## 题目信息

\- 题目名：Going in circles  
\- 类型：Crypto  
\- 附件：`task/[chal.py](http://chal.py)`  
\- 远程：`52.59.124.14:5100`

\---

## 静态分析

先看附件代码：

```python  
def reduce(a,f):  
while (l := a.bit_length()) > BITS:  
a ^= f << (l - BITS)  
return a  
```

其中 `BITS = 32`，并且服务端输出：

1\. `r = reduce(flag, f)`  
2\. `f`（随机 32-bit）

这实际上是把整数按二进制位看成 GF(2) 上的多项式，然后做多项式长除，取余数。   
也就是每次给出同一个未知多项式 $A(x)$（flag）在随机模多项式 $F_i(x)$ 下的余数：

$$  
A(x) \equiv R_i(x) \pmod{F_i(x)}  
$$

\---

## 核心思路

对同一个未知 $A(x)$，收集足够多组同余关系后，用 GF(2) 上的 CRT 逐步合并：

已知：

$$  
X \equiv x \pmod{M},\quad X \equiv r \pmod{f}  
$$

当 $\gcd(M, f)=1$ 时可写成：

$$  
k \equiv (r - x)\cdot M^{-1} \pmod f  
$$  
$$  
x' = x + M\cdot k,\quad M' = M\cdot f  
$$

在 GF(2) 中减法就是异或，所以实现时全部用按位 XOR 即可。   
当 $M$ 的总次数（位长）超过 flag 的次数时，解唯一，$x$ 就是原始 flag。

\---

## 失败与排查记录

1\. 首先尝试把单次输出当“哈希逆向”处理，这条路不成立，因为每次随机 `f` 都不一样。  
2\. 尝试直接线性方程组（固定未知位长）可做，但未知长度不方便，且实现成本更高。  
3\. 最终采用增量 CRT：只接收与当前模多项式互素的样本，速度和稳定性都更好。  
4\. 远程偶发空响应（返回空字节），在脚本里加了重试和短等待解决。

\---

## 实现要点

\- 纯 Python 实现 GF(2) 多项式运算：乘法、除法取模、gcd、扩展欧几里得求逆。  
\- 连远程批量采样；每个连接取一条 `r f`。  
\- 增量合并同余后，提取形如 `xxxx{...}` 的 token。  
\- 用新样本二次校验候选，确保不是误命中。

完整脚本：`solution/[solution.py](http://solution.py)`

运行：

```bash  
python3 solution/[solution.py](http://solution.py)  
```

\---

## 结果

```text  
ENO{CRC_is_just_some_modular_remainder}  
```

说明：本题真实前缀为 `ENO{}`，不是 `flag{}`。

### Exploit  
#### cry/Going/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import argparse  
import re  
import socket  
import time

BITS = 32

def poly_deg(p: int) -> int:  
return p.bit_length() - 1

def poly_mul(a: int, b: int) -> int:  
r = 0  
while b:  
if b & 1:  
r ^= a  
a <<= 1  
b >>= 1  
return r

def poly_divmod(a: int, b: int) -> tuple[int, int]:  
if b == 0:  
raise ZeroDivisionError("polynomial division by zero")  
q = 0  
r = a  
db = poly_deg(b)  
while r and poly_deg(r) >= db:  
shift = poly_deg(r) - db  
q ^= 1 << shift  
r ^= b << shift  
return q, r

def poly_mod(a: int, m: int) -> int:  
return poly_divmod(a, m)[1]

def poly_gcd(a: int, b: int) -> int:  
while b:  
a, b = b, poly_mod(a, b)  
return a

def poly_egcd(a: int, b: int) -> tuple[int, int, int]:  
x0, y0 = 1, 0  
x1, y1 = 0, 1  
while b:  
q, r = poly_divmod(a, b)  
a, b = b, r  
x0, x1 = x1, x0 ^ poly_mul(q, x1)  
y0, y1 = y1, y0 ^ poly_mul(q, y1)  
return a, x0, y0

def poly_inv(a: int, m: int) -> int:  
g, x, _ = poly_egcd(a, m)  
if g != 1:  
raise ValueError("not invertible")  
return poly_mod(x, m)

def reduce_checksum(a: int, f: int) -> int:  
while (l := a.bit_length()) > BITS:  
a ^= f << (l - BITS)  
return a

def fetch_sample(host: str, port: int, timeout_s: float, retries: int) -> tuple[int, int] | None:  
for _ in range(retries):  
try:  
with socket.create_connection((host, port), timeout=timeout_s) as s:  
s.settimeout(timeout_s)  
data = b""  
while True:  
try:  
chunk = s.recv(4096)  
except socket.timeout:  
break  
if not chunk:  
break  
data += chunk  
m = re.search(rb"(\d+)\s+(\d+)", data)  
if m:  
return int(m.group(1)), int(m.group(2))  
except OSError:  
pass  
time.sleep(0.05)  
return None

def extract_token(x: int) -> str | None:  
raw = x.to_bytes((x.bit_length() + 7) // 8, "big")  
patterns = [  
rb"flag\\{[ -~]{1,200}?\\}",  
rb"[A-Za-z]{2,12}\\{[ -~]{1,200}?\\}",  
]  
for pat in patterns:  
m = re.search(pat, raw)  
if m:  
return m.group(0).decode("utf-8", errors="replace")  
return None

def verify_candidate(  
cand: str,  
host: str,  
port: int,  
timeout_s: float,  
retries: int,  
rounds: int,  
) -> bool:  
target = int.from_bytes(cand.encode(), "big")  
success = 0  
for _ in range(rounds):  
sample = fetch_sample(host, port, timeout_s, retries)  
if sample is None:  
continue  
r, f = sample  
if reduce_checksum(target, f) == r:  
success += 1  
return success == rounds

def solve(  
host: str,  
port: int,  
max_samples: int,  
min_mod_bits: int,  
timeout_s: float,  
retries: int,  
verify_rounds: int,  
) -> tuple[str, int, int, int]:  
x = 0  
mod_all = 1  
raw_count = 0  
used_count = 0

for _ in range(max_samples):  
sample = fetch_sample(host, port, timeout_s, retries)  
if sample is None:  
continue

raw_count += 1  
r, f = sample  
if f in (0, 1):  
continue  
if poly_gcd(mod_all, f) != 1:  
continue

inv = poly_inv(poly_mod(mod_all, f), f)  
delta = r ^ poly_mod(x, f)  
k = poly_mod(poly_mul(delta, inv), f)  
x ^= poly_mul(mod_all, k)  
mod_all = poly_mul(mod_all, f)  
used_count += 1

if used_count % 5 == 0:  
print(f"[+] raw={raw_count} used={used_count} mod_bits={mod_all.bit_length()}")

if mod_all.bit_length() < min_mod_bits:  
continue

cand = extract_token(x)  
if cand is None:  
continue  
if verify_candidate(cand, host, port, timeout_s, retries, verify_rounds):  
return cand, raw_count, used_count, mod_all.bit_length()

raise RuntimeError("failed to recover flag within sample budget")

def main() -> None:  
parser = argparse.ArgumentParser(description="Solve Going in circles by polynomial CRT over GF(2).")  
parser.add_argument("--host", default="52.59.124.14")  
parser.add_argument("--port", type=int, default=5100)  
parser.add_argument("--max-samples", type=int, default=1200)  
parser.add_argument("--min-mod-bits", type=int, default=450)  
parser.add_argument("--timeout", type=float, default=4.0)  
parser.add_argument("--retries", type=int, default=8)  
parser.add_argument("--verify-rounds", type=int, default=20)  
args = parser.parse_args()

flag, raw_count, used_count, mod_bits = solve(  
host=args.host,  
port=args.port,  
max_samples=args.max_samples,  
min_mod_bits=args.min_mod_bits,  
timeout_s=args.timeout,  
retries=args.retries,  
verify_rounds=args.verify_rounds,  
)  
print(f"[+] recovered: {flag}")  
print(f"[+] stats: raw={raw_count} used={used_count} mod_bits={mod_bits}")

if __name__ == "__main__":  
main()  
```

\---
