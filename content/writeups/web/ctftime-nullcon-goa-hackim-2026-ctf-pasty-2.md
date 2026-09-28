---
title: "Pasty - Nullcon Goa HackIM 2026 CTF"
category: "web"
type: "writeup"
tags: ["web", "signature-forgery", "crypto", "xor", "pasty", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: web/Pasty"
source:
  name: "CTFtime writeup #40549"
  url: "https://ctftime.org/writeup/40549"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Pasty"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Pasty
- **Author team:** 正规子群.AI
- **CTFtime tags:** web, signature-forgery, crypto
- **CTFtime:** <https://ctftime.org/writeup/40549>

---
## 115 Pasty

\- Category: `web`  
\- Value: `50`  
\- Solves: `226`  
\- Solved by me: `True`  
\- Local directory: `web/Pasty`

### 题目描述  
> Check out our new secure pastebin service! We rolled our own cryptographic signatures to protect paste access - after all, why trust those boring standard libraries when you can build something custom?  
>  
> Can you prove that our homebrewed crypto isn't as secure as we think and get access to the 'flag' paste?  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5005`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/a7e6d6b4d46e81503697f82cdfb04892/sig.php?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4N30.aYqlNA.WWz40oM2J9U2Y68tngMBEhcIaxw>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Pasty Web Writeup

\---

## 题目信息

比赛名未知（题目目录按挑战名 `Pasty` 组织）。

目标服务：`http://52.59.124.14:5005`   
已知签名代码位于 `task/sig.php`。

目标是访问 `id=flag` 的 paste，需要构造合法 `sig`。

\---

## 源码审计

`task/sig.php`:

```php  
function _x($a,$b){$r='';for($i=0;$i<strlen($a);$i++)$r.=chr(ord($a[$i])^ord($b[$i]));return $r;}  
function compute_sig($d,$k){$h=hash('sha256',$d,1);$m=substr(hash('sha256',$k,1),0,24);$o='';for($i=0;$i<4;$i++){$s=$i<<3;$b=substr($h,$s,8);$p=(ord($h[$s])%3)<<3;$c=substr($m,$p,8);$o.=($i?_x(_x($b,$c),substr($o,$s-8,8)):_x($b,$c));}return $o;}  
```

设：

\- $h=\text{SHA256}(d)$，按 8 字节分块为 $b_0,b_1,b_2,b_3$。  
\- $m=\text{SHA256}(k)[0:24]$，按 8 字节分块为 $k_0,k_1,k_2$。  
\- 选择器 $p_i = h[8i] \bmod 3$。  
\- 输出分块 $s_i$。

则循环等价于：

\- $s_0 = b_0 \oplus k_{p_0}$  
\- $s_1 = b_1 \oplus k_{p_1} \oplus s_0$  
\- $s_2 = b_2 \oplus k_{p_2} \oplus s_1$  
\- $s_3 = b_3 \oplus k_{p_3} \oplus s_2$

这是可线性化的异或链，不是安全的 MAC 结构。

\---

## 尝试过程含失败路线

1\. 先尝试把它当成“类 HMAC”做长度扩展：失败。因为这里并不是 `hash(key || msg)` 的直接比较，而是对 `SHA256(msg)` 的分块再和 key 分块做线性混合。  
2\. 尝试从单个样本直接猜完整签名：不可行，信息不足。  
3\. 重新整理方程后发现可从合法样本直接恢复 key 分块，问题变成线性代数，成功。

\---

## 关键推导

定义前缀异或：

\- $B_i = b_0 \oplus b_1 \oplus \cdots \oplus b_i$  
\- $K_i = k_{p_0} \oplus k_{p_1} \oplus \cdots \oplus k_{p_i}$

由递推式可得：

$$s_i = B_i \oplus K_i$$

因此：

$$T_i := s_i \oplus B_i = K_i$$

进一步消去前缀：

\- $k_{p_0} = T_0$  
\- $k_{p_1} = T_1 \oplus T_0$  
\- $k_{p_2} = T_2 \oplus T_1$  
\- $k_{p_3} = T_3 \oplus T_2$

也就是说，拿到一组合法 `(id, sig)` 后，能直接恢复该样本涉及到的每个 key 分块值。   
`create.php` 提供签名 oracle，我们多创建几个 paste 即可覆盖 $k_0,k_1,k_2$ 三块。

覆盖后即可对任意目标（如 `id=flag`）本地计算合法签名。

\---

## 利用脚本

脚本：`solution/[solution.py](http://solution.py)`

功能：

1\. 调用 `create.php` 收集合法 `(id, sig)`；  
2\. 线性恢复 `SHA256(secret)` 的前三个 8-byte 分块；  
3\. 伪造 `id=flag` 的 `sig`；  
4\. 请求 `view.php?id=flag&sig=...` 并提取 flag。

运行：

```bash  
python3 solution/[solution.py](http://solution.py)  
```

\---

## 运行结果

本地实测成功访问 `id=flag` paste，得到：

```text  
ENO{cr3at1v3_cr7pt0_c0nstruct5_cr4sh_c4rd5}  
```

\---

## 结论

该“自制签名”把安全性建立在线性异或结构上，且暴露了签名 oracle（`create.php`），导致攻击者可恢复内部 key 分块并对任意消息伪造签名。   
这说明 MAC 设计不应自创，应使用标准方案（如 HMAC-SHA256）并避免可被批量查询的弱验签接口设计。

### Exploit  
#### web/Pasty/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import argparse  
import hashlib  
import os  
import re  
from typing import List, Optional  
from urllib.parse import parse_qs, unquote, urlparse

import requests

def bxor(a: bytes, b: bytes) -> bytes:  
return bytes(x ^ y for x, y in zip(a, b))

def split8(data: bytes) -> List[bytes]:  
return [data[i:i + 8] for i in range(0, len(data), 8)]

def parse_created_url(location_header: str) -> tuple[str, bytes]:  
# Location: index.php?msg=created&url=http%3A%2F%2Fhost%2Fview.php%3Fid%3D...%26sig%3D...  
m = re.search(r"(?:^|&)url=([^&]+)", location_header)  
if not m:  
raise ValueError(f"Cannot find encoded url in Location header: {location_header!r}")

view_url = unquote(m.group(1))  
q = parse_qs(urlparse(view_url).query)  
paste_id = q["id"][0]  
sig = bytes.fromhex(q["sig"][0])  
return paste_id, sig

def recover_key_blocks_from_pair(paste_id: str, sig: bytes) -> tuple[List[int], List[bytes]]:  
h = hashlib.sha256(paste_id.encode()).digest()  
b = split8(h)  
s = split8(sig)

# t[i] = K_prefix[i] = s[i] xor (b0 xor ... xor bi)  
t: List[bytes] = []  
px = b"\x00" * 8  
for i in range(4):  
px = bxor(px, b[i])  
t.append(bxor(s[i], px))

selectors = [h[i * 8] % 3 for i in range(4)]  
recovered = [b"" for _ in range(4)]  
recovered[0] = t[0]  
recovered[1] = bxor(t[1], t[0])  
recovered[2] = bxor(t[2], t[1])  
recovered[3] = bxor(t[3], t[2])  
return selectors, recovered

def forge_signature(message: str, key_blocks: List[bytes]) -> str:  
h = hashlib.sha256(message.encode()).digest()  
b = split8(h)  
selectors = [h[i * 8] % 3 for i in range(4)]

out: List[bytes] = []  
for i in range(4):  
chunk = bxor(b[i], key_blocks[selectors[i]])  
if i > 0:  
chunk = bxor(chunk, out[i - 1])  
out.append(chunk)

return b"".join(out).hex()

def solve(base: str, target_id: str, max_samples: int, timeout_sec: int) -> tuple[str, str]:  
sess = requests.Session()

key_blocks: List[Optional[bytes]] = [None, None, None]

for i in range(1, max_samples + 1):  
content = os.urandom(8).hex()  
r = [sess.post](http://sess.post)(  
f"{base}/create.php",  
data={"content": content},  
allow_redirects=False,  
timeout=timeout_sec,  
)  
location = r.headers.get("Location", "")  
paste_id, sig = parse_created_url(location)

selectors, recovered = recover_key_blocks_from_pair(paste_id, sig)  
for idx, block in zip(selectors, recovered):  
if key_blocks[idx] is None:  
key_blocks[idx] = block  
elif key_blocks[idx] != block:  
raise RuntimeError("Recovered key blocks conflict; server behavior changed or parsing failed.")

known = sum(x is not None for x in key_blocks)  
print(f"[+] sample {i:02d}, selectors={selectors}, recovered={known}/3")  
if known == 3:  
break

if any(x is None for x in key_blocks):  
raise RuntimeError("Failed to recover all key blocks; increase --max-samples.")

blocks = [x for x in key_blocks if x is not None]  
forged_sig = forge_signature(target_id, blocks)  
view = sess.get(f"{base}/view.php", params={"id": target_id, "sig": forged_sig}, timeout=timeout_sec)

body = view.text  
# Flexible extraction for different CTF flag prefixes.  
m = re.search(r"([A-Za-z0-9_]+\\{[^{}\n]+\\})", body)  
found_flag = m.group(1) if m else ""  
return forged_sig, found_flag

def main() -> None:  
parser = argparse.ArgumentParser(description="Exploit Pasty custom signature scheme")  
parser.add_argument("--base", default="http://52.59.124.14:5005", help="Base URL")  
parser.add_argument("--target-id", default="flag", help="Paste id to access")  
parser.add_argument("--max-samples", type=int, default=40, help="Max create.php requests")  
parser.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds")  
args = parser.parse_args()

forged_sig, found_flag = solve(args.base.rstrip("/"), args.target_id, args.max_samples, args.timeout)  
print(f"[+] forged sig for id={args.target_id!r}: {forged_sig}")  
if found_flag:  
print(f"[+] flag: {found_flag}")  
else:  
print("[-] Could not auto-extract flag from response body.")

if __name__ == "__main__":  
main()  
```

\---
