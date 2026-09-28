---
title: "TLS - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["oracle", "crypto", "rsa", "aes", "padding-oracle", "cbc", "chinese-remainder", "proof-of-work", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: cry/TLS"
source:
  name: "CTFtime writeup #40562"
  url: "https://ctftime.org/writeup/40562"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "TLS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** TLS
- **Author team:** 正规子群.AI
- **CTFtime tags:** oracle, crypto, rsa
- **CTFtime:** <https://ctftime.org/writeup/40562>

---
## 101 TLS

\- Category: `cry`  
\- Value: `107`  
\- Solves: `132`  
\- Solved by me: `True`  
\- Local directory: `cry/TLS`

### 题目描述  
> Welcome to my TLS 0.1 encryption protocol. It features a hybrid encryption scheme while managing a good coding style.

### 连接信息  
\- `52.59.124.14:5104`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/e71234096eec51e6970c1078ae1e3cf5/chall.py?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4MH0.aYqlOw.nNPQVgIkdNV7qTfaxDQEPHWErQM>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# TLS

\---

## 题目信息

\- 类型：Crypto  
\- 目标：恢复服务启动时输出密文对应的明文（flag）  
\- 远端：`52.59.124.14:5104`  
\- 附件：`task/[chal.py](http://chal.py)`

\---

## 静态审计

先读源码可得协议格式：

\- 密文结构：`l(4B) || iv(16B) || enc_msg(l bytes) || enc_key(RSA)`  
\- 对称加密：`AES-CBC + PKCS#7`  
\- 混合加密：`enc_key = key^e mod n`，其中 `key = 00..00(8B) || random(8B)`

关键函数在 `decrypt()`：

1\. 先做 RSA 解密（CRT 优化分支）得到 `key`。  
2\. 若 `key > 2^{128}` 抛异常。  
3\. 再做 AES 解密与去填充。

CRT 合成代码是：

$$  
h = invq \cdot (m_p - m_q) \bmod q,\quad key = m_q + hq \bmod n  
$$

但这里把 `invq`（$q^{-1} \bmod p$）错误地用于 `\bmod q` 的合成，公式不正确。

\---

## 失败尝试与排除

1\. 直接爆破 64-bit AES key：复杂度 $2^{64}$，不可行。  
2\. 走常规 RSA 攻击（低指数、直接开根）：`e=65537`，不满足小指数明文开根条件。  
3\. 依赖随机 padding oracle：信号噪声大，且不稳定。

最终改为构造“确定性 oracle”。

\---

## 核心利用思路

### 1. 把交互变成稳定判定 oracle

构造查询时令 `l=1`，即 `enc_msg` 长度不是 16 的倍数。这样在 RSA key 检查通过后，必然触发 `PaddingError`，服务返回 `invalid padding`。

因此：

\- 若返回 `invalid padding`：说明 RSA 阶段通过了 `key <= 2^{128}` 检查。  
\- 若返回 `something else went wrong`：说明 RSA 阶段未通过（通常是 `key > 2^{128}`）。

这就得到一个稳定布尔 oracle。

### 2. 利用 RSA 乘法同态做阈值查询

设目标 `enc_key = c_0 = m^e \bmod n`，其中真实 `m` 是 64-bit 小整数（因为前 8 字节为 0）。

查询：

$$  
c_t = c_0 \cdot t^e \bmod n  
$$

解密对应明文为：

$$  
m_t = m \cdot t \pmod n  
$$

由于 $m < 2^{64}$ 且我们选取的 $t$ 范围远小于 $n$，有 $m\cdot t < n$，可视为普通整数乘法。于是 oracle 本质判定：

$$  
m\cdot t \le 2^{128}  
$$

定义

$$  
T = \max\\{t \mid m t \le 2^{128}\\}  
$$

可通过二分获得 `T`。随后

$$  
\left\lfloor\frac{2^{128}}{T+1}\right\rfloor + 1 \le m \le \left\lfloor\frac{2^{128}}{T}\right\rfloor  
$$

在本题该区间长度为 1，直接得到唯一 `m`。

### 3. 还原 AES key 并解密 flag

恢复出的 `m` 转为 16 字节大端即原 AES key，随后用题目给的 `iv` 与 `enc_msg` 做 AES-CBC 解密并去填充，得到 flag。

\---

## 代码与运行

\- 利用脚本：`solution/[solution.py](http://solution.py)`  
\- 默认远程模式：`python3 solution/[solution.py](http://solution.py)`  
\- 可选本地模式：`python3 solution/[solution.py](http://solution.py) LOCAL`

实测恢复结果：

```text  
ENO{Y4y_a_f4ctor1ng_0rac13}  
```

\---

## 最终 flag

```text  
ENO{Y4y_a_f4ctor1ng_0rac13}  
```

### Exploit  
#### cry/TLS/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import os  
import sys

# Ensure consistent terminal behavior  
os.environ.update({'PWNLIB_NOTERM': '1', 'TERM': 'linux'})

# KEEP EXACTLY AS IS: prevents namespace conflict with math.log  
from pwn import process, remote, ssh, context, log as pwnlog  
from Crypto.Cipher import AES  
from Crypto.Util.number import bytes_to_long, long_to_bytes

context.log_level = 'DEBUG' # Never hide logs initially

HOST = '52.59.124.14'  
PORT = 5104  
E = 65537  
BOUND = 1 << 128  
PROMPT = b'input cipher (hex): '

def unpad_pkcs7(msg: bytes):  
if not msg:  
return None  
pad_len = msg[-1]  
if pad_len < 1 or pad_len > 16:  
return None  
if msg[-pad_len:] != bytes([pad_len]) * pad_len:  
return None  
return msg[:-pad_len]

def parse_challenge_blob(blob: bytes):  
block_len = bytes_to_long(blob[:4])  
iv = blob[4:20]  
enc_msg = blob[20:20 + block_len]  
enc_key = bytes_to_long(blob[20 + block_len:])  
return iv, enc_msg, enc_key

def read_banner(io):  
n = int(io.recvline(timeout=5).strip())  
cipher = bytes.fromhex(io.recvline(timeout=5).strip().decode())  
io.recvuntil(PROMPT, timeout=5)  
return n, cipher

def make_oracle_payload(enc_key: int) -> bytes:  
# l = 1 forces a deterministic PaddingError after RSA key check succeeds.  
body = (1).to_bytes(4, 'big') + (b'\x00' * 16) + b'Z'  
return body + long_to_bytes(enc_key)

def oracle_leq_2pow128(io, n: int, c0: int, t: int) -> bool:  
c = (c0 * pow(t, E, n)) % n  
io.sendline(make_oracle_payload(c).hex().encode())  
line = io.recvline(timeout=5)  
if line is None:  
raise RuntimeError('oracle response timeout')  
text = line.decode(errors='ignore').strip()  
io.recvuntil(PROMPT, timeout=5)  
return text == 'invalid padding'

def recover_small_rsa_plain(io, n: int, c0: int) -> int:  
lo = 1  
hi = 1  
while oracle_leq_2pow128(io, n, c0, hi):  
lo = hi  
hi <<= 1  
if hi > (1 << 140):  
raise RuntimeError('failed to find false upper bound')

while lo + 1 < hi:  
mid = (lo + hi) // 2  
if oracle_leq_2pow128(io, n, c0, mid):  
lo = mid  
else:  
hi = mid

threshold = lo  
lower = BOUND // (threshold + 1) + 1  
upper = BOUND // threshold  
[pwnlog.info](http://pwnlog.info)(f'threshold={threshold}')  
[pwnlog.info](http://pwnlog.info)(f'key range=[{lower}, {upper}] (size={upper - lower + 1})')

if lower == upper:  
return lower

raise RuntimeError(f'non-unique key range: [{lower}, {upper}]')

def decrypt_flag_blob(cipher_blob: bytes, key_int: int) -> bytes:  
iv, enc_msg, _ = parse_challenge_blob(cipher_blob)  
key = key_int.to_bytes(16, 'big')  
raw = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(enc_msg)  
msg = unpad_pkcs7(raw)  
if msg is None:  
raise ValueError('invalid PKCS#7 after key recovery')  
return msg

def main():  
mode_local = len(sys.argv) >= 2 and sys.argv[1].upper() == 'LOCAL'

if mode_local:  
io = process(['python3', 'task/[chal.py](http://chal.py)'])  
else:  
host = HOST  
port = PORT  
if len(sys.argv) >= 2:  
host = sys.argv[1]  
if len(sys.argv) >= 3:  
port = int(sys.argv[2])  
io = remote(host, port, timeout=5)

try:  
n, cipher_blob = read_banner(io)  
_, _, c0 = parse_challenge_blob(cipher_blob)  
key_int = recover_small_rsa_plain(io, n, c0)  
flag = decrypt_flag_blob(cipher_blob, key_int)  
print(flag.decode(errors='replace'))  
finally:  
try:  
io.sendline(b'exit')  
except Exception:  
pass  
io.close()

if __name__ == '__main__':  
main()  
```

\---
