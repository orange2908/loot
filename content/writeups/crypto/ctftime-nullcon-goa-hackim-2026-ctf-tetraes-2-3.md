---
title: "Tetraes - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["custom-cipher", "oracle", "crypto", "aes", "z3", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: cry/Tetraes"
source:
  name: "CTFtime writeup #40560"
  url: "https://ctftime.org/writeup/40560"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Tetraes"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Tetraes
- **Author team:** 正规子群.AI
- **CTFtime tags:** custom-cipher, oracle, crypto
- **CTFtime:** <https://ctftime.org/writeup/40560>

---
## 100 Tetraes

\- Category: `cry`  
\- Value: `251`  
\- Solves: `84`  
\- Solved by me: `True`  
\- Local directory: `cry/Tetraes`

### 题目描述  
> I decided to use an encryption scheme that is suitable for critical infrastructure, so it must be secure, right?

### 连接信息  
\- `52.59.124.14:5103`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/1bed006fb788ad74eec03f9837382312/chall.py?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo3OX0.aYqlQA.DoaSIFfiM81X_Y_4y4DoOIncdrU>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Tetraes

\---

## 题目信息

\- Challenge: `Tetraes`  
\- 分值: `500`  
\- 远端: `52.59.124.14:5103`  
\- 交互目标: 恢复 16 字节密钥，最后输入十六进制密钥拿到 flag。

\---

## 文件结构

```text  
Tetraes  
├── [README.md](http://README.md)  
├── solution  
│ └── [solution.py](http://solution.py)  
└── task  
└── [chal.py](http://chal.py)  
```

\---

## 静态分析

题目核心逻辑在 `task/[chal.py](http://chal.py)`：

1\. 随机生成 `key = os.urandom(16)`。  
2\. 输出 `cipher.hex() = encrypt(key, key)`。  
3\. 提供任意明文加密 oracle：用户输入 hex，返回 `encrypt(message, key)`。  
4\. 用户输入最终 `user_key`，若等于 `key` 则输出 flag。

看起来像 AES，但实现并不标准：

\- 轮数是 16。  
\- `ark` 每轮多做了 `state[0][0] ^= (r ^ 42)`。  
\- `S` 盒不是 AES 标准 S 盒，且**不是置换**（有重复值）。

最关键漏洞是 S 盒的值域缺失 `0x63`：

$$0x63 \notin \\{S[x] \mid x\in[0,255]\\}$$

因此任意轮进入 `SubBytes` 之前的字节都不可能等于 `0x63`。

\---

## 失败尝试记录

### 尝试 1：直接 SMT 建模 16 轮

把 16 字节密钥设成 16 个 `BitVec(8)`，对多组明密文建立完整轮函数约束（含 S 盒查询、ShiftRows、MixColumns、轮密钥轮转），再让 Z3 求解。

结果：约束规模太大，求解时间明显不可接受（多次超时）。

### 尝试 2：把“末轮逆变换 + 不等式”交给 SMT

只建模末轮逆向：

$$V = \text{InvShiftRows}(\text{InvMixColumns}(C \oplus K_{16}))$$

并添加 16 个不等式：

$$V_{i,j} \neq 0x63$$

相比完整建模快一些，但仍然偏慢。

\---

## 正式解法

### 1. 只用最后一轮的结构性质

设某次查询的 16 字节密文为 $C$。末轮关系可写成：

$$C = \text{MixColumns}(\text{ShiftRows}(S(X))) \oplus \text{rk}_{16} \oplus \Delta$$

其中只有左上角字节额外异或常量 $\Delta = 16\oplus42$。

移项并逆变换：

$$U = C \oplus \text{rk}_{16} \oplus \Delta$$  
$$W = \text{InvMixColumns}(U)$$  
$$Y = \text{InvShiftRows}(W) = S(X)$$

因为 $0x63$ 不在 S 盒输出里，所以对任意字节有：

$$Y_{i,j} \neq 0x63$$

### 2. 单列拆分

`InvMixColumns` 按列独立，因此每列只涉及该列 4 个密钥字节。令某列密文向量为 $c=(c_0,c_1,c_2,c_3)$，列密钥为 $k=(k_0,k_1,k_2,k_3)$。

对 `InvMixColumns` 的四行系数：

$$A=\begin{bmatrix}  
14&11&13&9\\\  
9&14&11&13\\\  
13&9&14&11\\\  
11&13&9&14  
\end{bmatrix}$$

可得每行的“禁止值”形式：

$$\sum_t A_{r,t}k_t \neq 0x63 \oplus \sum_t A_{r,t}c_t \oplus \delta_r$$

其中第 0 列第 0 行额外包含常量修正（来自左上角 $\Delta$）。

每个样本会给每行排除 1 个 GF$(2^8)$ 值。大量样本后，每行 256 个候选里只剩 1 个未被排除值，记为 $v_r$，于是得到线性方程组：

$$A\cdot k = v$$

在 GF$(2^8)$ 上做高斯消元即可解出该列密钥。

4 列独立恢复后拼成完整 16 字节密钥。

### 3. 速度优化

为了减少网络 RTT，不是每次只发 1 块，而是每次发送 `32` 个 block（即 `512` 字节随机明文）。

这样 80 次请求就有约 2560 个样本，通常可稳定唯一化并恢复密钥。

\---

## 关键实现

实现文件：`solution/[solution.py](http://solution.py)`

\- `--remote --submit`：连接远端并自动提交。  
\- 默认本地模式：`process(['python3', 'task/[chal.py](http://chal.py)'])`，用于回归验证。  
\- 使用 GF$(2^8)$ 运算、GF 逆元表、4x4 高斯消元恢复列密钥。

运行命令：

```bash  
python3 solution/[solution.py](http://solution.py) \--remote --submit  
```

\---

## 验证结果

远端实测成功恢复密钥并拿到 flag。

```text  
ENO{a1l_cop5_ar3_br0adca5t1ng_w1th_t3tra}  
```

### Exploit  
#### cry/Tetraes/solution/[solution.py](http://solution.py)

```python  
import os, sys  
# Ensure consistent terminal behavior  
os.environ.update({'PWNLIB_NOTERM': '1', 'TERM': 'linux'})

# KEEP EXACTLY AS IS: prevents namespace conflict with math.log  
from pwn import process, remote, ssh, context, log as pwnlog

context.log_level = 'DEBUG' # Never hide logs initially  
context.timeout = 5

import importlib.util  
import pathlib  
import re

HOST = "52.59.124.14"  
PORT = 5103  
DELTA = 16 ^ 42  
INV_MAT = (  
(14, 11, 13, 9),  
(9, 14, 11, 13),  
(13, 9, 14, 11),  
(11, 13, 9, 14),  
)  
BASE_DIR = pathlib.Path(__file__).resolve().parents[1]  
TASK_SCRIPT = BASE_DIR / "task" / "[chal.py](http://chal.py)"

def gmul(a: int, b: int) -> int:  
p = 0  
for _ in range(8):  
if b & 1:  
p ^= a  
hi = a & 0x80  
a = (a << 1) & 0xFF  
if hi:  
a ^= 0x1B  
b >>= 1  
return p

MUL = {c: [gmul(c, x) for x in range(256)] for c in (9, 11, 13, 14)}  
GF_INV = [0] * 256  
for x in range(1, 256):  
for y in range(1, 256):  
if gmul(x, y) == 1:  
GF_INV[x] = y  
break

def solve_gf_4x4(a_mat, b_vec):  
mat = [list(a_mat[i]) + [b_vec[i]] for i in range(4)]  
row = 0  
for col in range(4):  
piv = None  
for r in range(row, 4):  
if mat[r][col] != 0:  
piv = r  
break  
if piv is None:  
raise ValueError("singular system")  
mat[row], mat[piv] = mat[piv], mat[row]

inv = GF_INV[mat[row][col]]  
for c in range(col, 5):  
mat[row][c] = gmul(mat[row][c], inv)

for r in range(4):  
if r == row:  
continue  
factor = mat[r][col]  
if factor == 0:  
continue  
for c in range(col, 5):  
mat[r][c] ^= gmul(factor, mat[row][c])  
row += 1  
return [mat[i][4] for i in range(4)]

def load_encrypt():  
spec = importlib.util.spec_from_file_location("chal_mod", TASK_SCRIPT)  
if spec is None or spec.loader is None:  
raise RuntimeError(f"failed to load {TASK_SCRIPT}")  
mod = importlib.util.module_from_spec(spec)  
spec.loader.exec_module(mod)  
return mod.encrypt

def parse_cipher_line(io):  
io.recvuntil(b"cipher.hex() = '")  
hex_str = io.recvuntil(b"'", drop=True).decode()  
return bytes.fromhex(hex_str)

def update_forbidden_sets(ct_block: bytes, forbidden):  
for col in range(4):  
c0 = ct_block[0 * 4 + col]  
c1 = ct_block[1 * 4 + col]  
c2 = ct_block[2 * 4 + col]  
c3 = ct_block[3 * 4 + col]

for row, (a0, a1, a2, a3) in enumerate(INV_MAT):  
rhs = 0x63 ^ MUL[a0][c0] ^ MUL[a1][c1] ^ MUL[a2][c2] ^ MUL[a3][c3]  
if col == 0:  
rhs ^= MUL[a0][DELTA]  
forbidden[col][row].add(rhs)

def try_recover_key(forbidden):  
key = [0] * 16  
for col in range(4):  
vals = []  
for row in range(4):  
miss = [x for x in range(256) if x not in forbidden[col][row]]  
if len(miss) != 1:  
return None  
vals.append(miss[0])

col_key = solve_gf_4x4(INV_MAT, vals)  
for row in range(4):  
key[row * 4 + col] = col_key[row]  
return bytes(key)

def connect(use_remote: bool):  
if use_remote:  
return remote(HOST, PORT)  
return process(["python3", str(TASK_SCRIPT)])

def main():  
use_remote = "--remote" in sys.argv  
force_submit = "--submit" in sys.argv  
max_queries = 300  
blocks_per_query = 32  
min_samples = 800  
check_step = 5  
submit = use_remote or force_submit

encrypt = load_encrypt()  
io = connect(use_remote)

try:  
banner_ct = parse_cipher_line(io)  
io.recvuntil(b"message to encrypt: ")  
[pwnlog.info](http://pwnlog.info)(f"banner E_k(k): {banner_ct.hex()}")  
context.log_level = "INFO"

forbidden = [[set() for _ in range(4)] for _ in range(4)]  
key = None

total_samples = 0  
for q in range(1, max_queries + 1):  
msg = os.urandom(16 * blocks_per_query).hex().encode()  
io.sendline(msg)  
ct = parse_cipher_line(io)  
io.recvuntil(b"message to encrypt: ")  
block_count = len(ct) // 16  
for i in range(block_count):  
update_forbidden_sets(ct[i * 16 : (i + 1) * 16], forbidden)  
total_samples += block_count

if q % 20 == 0:  
[pwnlog.info](http://pwnlog.info)(f"queries={q}, samples={total_samples}")

if total_samples >= min_samples and q % check_step == 0:  
cand = try_recover_key(forbidden)  
if cand is not None and encrypt(cand, cand) == banner_ct:  
key = cand  
pwnlog.success(  
f"recovered key after {q} queries ({total_samples} samples): {key.hex()}"  
)  
break

if key is None:  
raise RuntimeError("failed to recover key within max queries")

if not submit:  
print(f"[+] key = {key.hex()}")  
return

io.sendline(b"end")  
io.recvuntil(b"Can you tell me the key in hex? ")  
io.sendline(key.hex().encode())  
out = io.recvall(timeout=5).decode(errors="ignore")  
print(out)  
m = re.search(r"(?:flag|ENO)\\{[^}\n]+\\}", out)  
if m:  
pwnlog.success(f"flag: {m.group(0)}")  
else:  
pwnlog.warning("flag pattern not found in output")  
finally:  
io.close()

if __name__ == "__main__":  
main()  
```

\---
