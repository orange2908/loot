---
title: "Matrixfun II - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["linear-algebra", "crypto", "affine", "chinese-remainder", "proof-of-work", "base64", "eval", "number-theory", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: cry/MatrixfunII"
source:
  name: "CTFtime writeup #40563"
  url: "https://ctftime.org/writeup/40563"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Matrixfun II"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Matrixfun II
- **Author team:** 正规子群.AI
- **CTFtime tags:** linear-algebra, crypto, affine
- **CTFtime:** <https://ctftime.org/writeup/40563>

---
## 98 Matrixfun II

\- Category: `cry`  
\- Value: `50`  
\- Solves: `157`  
\- Solved by me: `True`  
\- Local directory: `cry/MatrixfunII`

### 题目描述  
> I wanted to implement post-quantum-cryptography and I am quite sure I made no error.

### 连接信息  
\- `52.59.124.14:5101`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/02ef0004bdb26f7f764c92217550600c/chall.py?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo3OH0.aYqlMQ.xYR9cn6fFGM1eUcFOaEZ_HCLoyA>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Matrixfun II 解题记录

\---

## 题目信息

\- Challenge: `Matrixfun II`  
\- 类型: Crypto  
\- 远程: `52.59.124.14:5101`  
\- 题目给出的核心代码在 `task/[chal.py](http://chal.py)`

\---

## 静态分析

题目加密流程：

1\. 把输入消息做 `base64.b64encode`。  
2\. 用 `=` 填充到 $16$ 的倍数（注意：即使本来就是 $16$ 的倍数，也会再补 $16$ 个 `=`）。  
3\. 每 $16$ 个字符做一次仿射变换：  
$$  
y = A x + b \pmod{65}  
$$  
其中字符映射表是：  
`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=`，长度为 $65$。

启动时会先打印一次 `flag` 的密文，然后给我们一个可无限调用的加密 oracle（十六进制输入）。

\---

## 攻击思路

这是标准的“可选明文 + 仿射分组”场景，目标是恢复 $A,b$。

关键点：

\- 当我们发送 `12` 字节输入时，base64 长度恰好是 `16` 字符，对应 1 个完整可控块。  
\- base64 字符只能来自标准 64 字符集（不含 `=`），但足够恢复矩阵。  
\- 选基准块 `"a"*16`（在自定义 alphabet 中索引全是 $0$）：  
$$  
y_0 = A\cdot 0 + b = b  
$$  
所以直接拿到 $b$。  
\- 再逐列构造 `"a"*16` 里第 $i$ 位改成 `b`（索引从 $0$ 变 $1$），得到：  
$$  
y_i - y_0 = A e_i  
$$  
即第 $i$ 列。

总计 17 次查询恢复完整 $A,b$。

\---

## 数学求解细节

模数 $65=5\times 13$，不是素数域。直接在 $\mathbb{Z}_{65}$ 上做高斯消元容易踩“主元不可逆”的坑。

我采用 CRT 分解：

1\. 在 $\bmod 5$ 上求 $A^{-1}$。  
2\. 在 $\bmod 13$ 上求 $A^{-1}$。  
3\. 解密时先分别求  
$$  
x_5 = A^{-1}(y-b) \bmod 5,  
\quad  
x_{13} = A^{-1}(y-b) \bmod 13  
$$  
4\. 再按 CRT 合并到 $\bmod 65$：  
$$  
x \equiv 26x_5 + 40x_{13} \pmod{65}  
$$  
因为 $13^{-1}\bmod 5=2$，$5^{-1}\bmod 13=8$。

得到每个块的字符索引后，映射回字符，拼成“被 `=` 补到 16 倍数的 base64 串”，最后去掉额外补位（候选 $4/8/12/16$）再 base64 解码即可。

\---

## 失败尝试与修正

1\. 最初打算直接求 $A^{-1}\bmod 65$，但环上不可逆元素很多，不够稳。  
2\. 改为 CRT（模 5 与模 13）后稳定解出。  
3\. 首版脚本只把 `flag{` 当成功标记，实际题目前缀是 `ENO{`，导致拿到明文后还在继续重连；已修复为检测 `{...}`。

\---

## 代码与验证

\- 利用脚本：`solution/[solution.py](http://solution.py)`  
\- 运行命令：

```bash  
python3 solution/[solution.py](http://solution.py)  
```

实测输出：

```text  
ENO{l1ne4r_alg3br4_i5_ev3rywh3re}  
```

\---

## Flag

```text  
ENO{l1ne4r_alg3br4_i5_ev3rywh3re}  
```

### Exploit  
#### cry/MatrixfunII/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import ast  
import base64  
import os  
from typing import List, Tuple

os.environ.update({'PWNLIB_NOTERM': '1', 'TERM': 'linux'})

# KEEP EXACTLY AS IS: prevents namespace conflict with math.log  
from pwn import process, remote, ssh, context, log as pwnlog

context.log_level = 'DEBUG'

ALPHABET = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='  
MOD = len(ALPHABET) # 65  
N = 16  
HOST = '52.59.124.14'  
PORT = 5101

def parse_int_list(line: bytes) -> List[int]:  
obj = ast.literal_eval(line.decode().strip())  
if not isinstance(obj, list) or not all(isinstance(x, int) for x in obj):  
raise ValueError(f'invalid list line: {line!r}')  
return obj

def recv_cipher_line(io) -> List[int]:  
line = io.recvline(timeout=6)  
if not line:  
raise EOFError('remote closed before ciphertext line')  
return parse_int_list(line)

def send_hex_query(io, raw: bytes) -> List[int]:  
io.sendlineafter(b'enter your message (in hex): ', raw.hex().encode())  
line = io.recvline(timeout=6)  
if not line:  
raise EOFError('remote closed before oracle response')  
return parse_int_list(line)

def block_to_input_bytes(block16: str) -> bytes:  
if len(block16) != N:  
raise ValueError('block must be length 16')  
if '=' in block16:  
raise ValueError('oracle control blocks should avoid =')  
return base64.b64decode(block16.encode(), validate=True)

def oracle_first_block(io, block16: str) -> List[int]:  
out = send_hex_query(io, block_to_input_bytes(block16))  
if len(out) < N:  
raise ValueError('oracle returned too short ciphertext')  
return out[:N]

def recover_A_b(io) -> Tuple[List[List[int]], List[int]]:  
base = 'a' * N  
y0 = oracle_first_block(io, base)  
b = y0[:]

A = [[0] * N for _ in range(N)]  
for col in range(N):  
s = list(base)  
s[col] = 'b'  
y = oracle_first_block(io, ''.join(s))  
for row in range(N):  
A[row][col] = (y[row] - y0[row]) % MOD

return A, b

def mat_vec_mul_mod(A: List[List[int]], v: List[int], p: int) -> List[int]:  
n = len(A)  
return [sum((A[i][j] * v[j]) for j in range(n)) % p for i in range(n)]

def invert_matrix_mod_prime(A: List[List[int]], p: int) -> List[List[int]]:  
n = len(A)  
M = []  
for i in range(n):  
row = [x % p for x in A[i]]  
row.extend(1 if i == j else 0 for j in range(n))  
M.append(row)

for c in range(n):  
pivot = None  
for r in range(c, n):  
if M[r][c] % p != 0:  
pivot = r  
break  
if pivot is None:  
raise ValueError(f'matrix is singular mod {p}')

if pivot != c:  
M[c], M[pivot] = M[pivot], M[c]

inv_pivot = pow(M[c][c], -1, p)  
for j in range(2 * n):  
M[c][j] = (M[c][j] * inv_pivot) % p

for r in range(n):  
if r == c:  
continue  
factor = M[r][c] % p  
if factor == 0:  
continue  
for j in range(2 * n):  
M[r][j] = (M[r][j] - factor * M[c][j]) % p

inv = [row[n:] for row in M]  
return inv

def crt_5_13(x5: int, x13: int) -> int:  
# x ≡ x5 (mod 5), x ≡ x13 (mod 13)  
# 13 * inv(13 mod 5) = 13 * 2 = 26  
# 5 * inv(5 mod 13) = 5 * 8 = 40  
return (26 * x5 + 40 * x13) % 65

def decrypt_block(y: List[int], A_inv_5: List[List[int]], A_inv_13: List[List[int]], b: List[int]) -> List[int]:  
c = [(y[i] - b[i]) % MOD for i in range(N)]  
c5 = [x % 5 for x in c]  
c13 = [x % 13 for x in c]

x5 = mat_vec_mul_mod(A_inv_5, c5, 5)  
x13 = mat_vec_mul_mod(A_inv_13, c13, 13)  
x = [crt_5_13(x5[i], x13[i]) for i in range(N)]  
return x

def indices_to_block(x: List[int]) -> str:  
return bytes(ALPHABET[i] for i in x).decode()

def affine_encrypt_block(A: List[List[int]], b: List[int], x: List[int]) -> List[int]:  
out = []  
for row in range(N):  
v = sum(A[row][j] * x[j] for j in range(N)) + b[row]  
out.append(v % MOD)  
return out

def decode_flag_from_padded_b64(padded_b64: str) -> Tuple[bytes, int]:  
# base64 output length is multiple of 4; extra pad to 16-byte blocks adds 4/8/12/16 '='  
candidates = []  
for extra in (4, 8, 12, 16):  
if len(padded_b64) <= extra:  
continue  
core = padded_b64[:-extra]  
if len(core) % 4 != 0:  
continue  
try:  
plain = base64.b64decode(core, validate=True)  
except Exception:  
continue  
candidates.append((plain, extra))

for plain, extra in candidates:  
if b'flag{' in plain:  
return plain, extra

if candidates:  
return candidates[0]

raise ValueError('failed to decode padded base64 string')

def solve_once() -> str:  
io = remote(HOST, PORT, timeout=6)  
try:  
target_cipher = recv_cipher_line(io)

A, b = recover_A_b(io)

# quick consistency check on one controlled block  
check_block = 'abcdEFGHijklMNOP'  
real_first = oracle_first_block(io, check_block)  
x = [ALPHABET.index(ch) for ch in check_block.encode()]  
pred_first = affine_encrypt_block(A, b, x)  
if real_first != pred_first:  
raise ValueError('oracle consistency check failed')

A_inv_5 = invert_matrix_mod_prime(A, 5)  
A_inv_13 = invert_matrix_mod_prime(A, 13)

if len(target_cipher) % N != 0:  
raise ValueError('target ciphertext length not aligned to 16')

recovered_b64_blocks = []  
for i in range(0, len(target_cipher), N):  
y = target_cipher[i:i + N]  
x_block = decrypt_block(y, A_inv_5, A_inv_13, b)  
recovered_b64_blocks.append(indices_to_block(x_block))

recovered_padded_b64 = ''.join(recovered_b64_blocks)  
plain, extra = decode_flag_from_padded_b64(recovered_padded_b64)

[pwnlog.info](http://pwnlog.info)(f'recovered padded b64: {recovered_padded_b64}')  
[pwnlog.info](http://pwnlog.info)(f'detected extra pad length: {extra}')  
return plain.decode(errors='replace')  
finally:  
try:  
io.close()  
except Exception:  
pass

def main() -> None:  
for attempt in range(1, 31):  
[pwnlog.info](http://pwnlog.info)(f'attempt {attempt}/30')  
try:  
flag = solve_once()  
print(flag)  
if '{' in flag and '}' in flag:  
return  
except Exception as exc:  
pwnlog.warning(f'attempt failed: {exc}')

raise SystemExit('failed to recover flag in 30 attempts')

if __name__ == '__main__':  
main()  
```

\---
