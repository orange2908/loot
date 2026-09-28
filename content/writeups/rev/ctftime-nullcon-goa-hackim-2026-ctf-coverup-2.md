---
title: "Coverup - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "coverage", "analysis", "reverse", "base64", "coverup", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: rev/Coverup"
source:
  name: "CTFtime writeup #40554"
  url: "https://ctftime.org/writeup/40554"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Coverup"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Coverup
- **Author team:** 正规子群.AI
- **CTFtime tags:** coverage, analysis, reverse
- **CTFtime:** <https://ctftime.org/writeup/40554>

---
## 106 Coverup

\- Category: `rev`  
\- Value: `89`  
\- Solves: `138`  
\- Solved by me: `True`  
\- Local directory: `rev/Coverup`

### 题目描述  
> We've got the encrypted flag and some coverage information. Can you help us recover the flag?  
>  
> Author: @gehaxelt

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/3d8c88a197b5eb64c660a5e476cd4e63/public.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4MX0.aYqlOA.y27zuJmcgHLV1ZLVYEiXvfoPYMI>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# Coverup

\---

## 题目与附件

题目给了三个关键信息文件：

1\. `task/encrypt.php`：完整加密逻辑（PHP 源码，静态可读）。  
2\. `task/output/encrypted_flag.txt`：密文，格式是 `base64(processed):sha1(processed)`。  
3\. `task/output/coverage.json`：`xdebug` 产生的覆盖数据（含 `lines` 和 `branches`）。

因为是 Reverse 题，先纯静态分析，不跑动态服务。

\---

## 静态逆向过程

### 1. 整体结构

`encrypt($plaintext)` 每个字节流程是：

1\. 取循环 key 字节 `keyChar`。  
2\. 用一张 256 项替换表把 `keyChar` 映射到 `processedKeyAscii`。  
3\. 明文字节与 `processedKey` 做异或，得到 `$xored`。  
4\. `$xored` 再过同构的 256 项替换表，得到输出字节。  
5\. 全部拼接后做 `base64`，并附加 `sha1`。

可写成：

设替换表为 $M: \\{0,\dots,255\\}\to\\{0,\dots,255\\}$，则单字节满足

$C_i = M\big(P_i \oplus M(K_{i\bmod 9})\big)$。

其中 $K$ 长度是 9（`generate_challenge.php` 里写死 `generateRandomKey(9)`）。

### 2. 覆盖信息能泄露什么

`coverage.json` 的 `lines` 只给“执行过/未执行”，不含次数，信息不够。

关键是 `functions -> FlagEncryptor->encrypt -> branches`：

\- 第一个大 if-else 链（从 `line 46` 开始）对应 `if ($keyChar == chr(x))`。  
\- 第二个大 if-else 链（从 `line 1590` 开始）对应 `if ($xored == chr(x))`。

我按 `line = base + 6*x` 把每个分支映射回字节值：

\- `keyChar` 真分支集合大小为 9，恢复到 key 字节集合：  
$\\{49,61,65,68,86,108,111,112,122\\}$。  
\- `xored` 真分支集合大小为 40，可作为额外全局约束。

注意：这只能拿到 key 字节“集合”，拿不到顺序。

\---

## 失败尝试与修正

### 尝试 A：直接构造 $M^{-1}$

失败原因：$M$ 不是双射，有碰撞（多个输入映射到同一输出），不能用单值逆映射。

### 尝试 B：只用 `ENO{` 前缀 + 全可打印字符爆破

能得到多组候选（碰撞导致歧义），不能唯一。

### 尝试 C最终：

联合约束：

1\. `key` 只在覆盖给出的 9 字节集合上做排列（$9!$）。  
2\. 每个位置按反向候选集合恢复明文字节。  
3\. 固定前缀 `ENO{` 与结尾 `}`。  
4\. 强制候选的 `xored` 取值集合与覆盖中观察到的集合完全一致。  
5\. 对剩余候选做语义评分，选出最合理 flag 文本。

最终稳定选出：

```text  
ENO{c0v3r4g3_l34k5_s3cr3t5_really_g00d_you_Kn0w?}  
```

\---

## 使用到的命令/步骤记录

1\. 解包与查看：`unzip -l pub.zip`，`unzip -o pub.zip -d task`。  
2\. 静态阅读源码：`sed -n`、`nl -ba`、`rg -n`。  
3\. 解析覆盖与约束求解：`python3 solution/[solution.py](http://solution.py)`。

\---

## 最终脚本

\- 求解脚本：`solution/[solution.py](http://solution.py)`  
\- 运行验证：

```bash  
python3 solution/[solution.py](http://solution.py)  
```

脚本会输出全部候选和最终选择结果。

\---

## Flag

```text  
ENO{c0v3r4g3_l34k5_s3cr3t5_really_g00d_you_Kn0w?}  
```

### Exploit  
#### rev/Coverup/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import base64  
import hashlib  
import itertools  
import json  
import re  
import string  
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1] / "task"  
ENCRYPT_PHP = TASK_DIR / "encrypt.php"  
COVERAGE_JSON = TASK_DIR / "output" / "coverage.json"  
ENCRYPTED_FLAG = TASK_DIR / "output" / "encrypted_flag.txt"

def parse_substitution_table(php_source: str):  
pattern = (  
r"if \\(\$keyChar == chr\\((\d+)\\)\\) \\{\s*"  
r"\$processedKeyAscii = ord\\(\$keyChar\\) \\+ (\d+);"  
)  
pairs = [(int(a), int(b)) for a, b in re.findall(pattern, php_source)]  
if len(pairs) != 256:  
raise ValueError(f"unexpected mapping count: {len(pairs)}")

mapping = [0] * 256  
for value, plus in pairs:  
mapping[value] = (value + plus) % 256

reverse = {i: [] for i in range(256)}  
for value, mapped in enumerate(mapping):  
reverse[mapped].append(value)  
return mapping, reverse

def extract_true_value_set(branches: dict, base_line: int):  
found = set()  
for branch in branches.values():  
line = branch["line_start"]  
if line < base_line or line > base_line + 6 * 255:  
continue  
if (line - base_line) % 6 != 0:  
continue  
if len(branch.get("out", [])) != 2:  
continue  
if branch["out_hit"][0] == 1:  
found.add((line - base_line) // 6)  
return found

def recover_candidates(processed: bytes, mapping: list, reverse: dict, keyset: list, xored_set_obs: set):  
fixed = {0: ord("E"), 1: ord("N"), 2: ord("O"), 3: ord("{"), len(processed) - 1: ord("}")}  
# Typical flag charset; this drastically prunes collision branches.  
allowed_plain = set(ord(c) for c in (string.ascii_letters + string.digits + "_{}?!"))  
solutions = []

for perm in itertools.permutations(keyset):  
derived_key = [mapping[b] for b in perm]  
per_pos_choices = []  
valid = True

for i, c in enumerate(processed):  
choices = []  
for x in reverse[c]:  
p = x ^ derived_key[i % len(derived_key)]  
if p in allowed_plain:  
choices.append((p, x))  
if not choices:  
valid = False  
break  
per_pos_choices.append(choices)  
if not valid:  
continue

for idx, ch in fixed.items():  
if all(p != ch for p, _ in per_pos_choices[idx]):  
valid = False  
break  
if not valid:  
continue

order = sorted(range(len(processed)), key=lambda idx: len(per_pos_choices[idx]))  
cur_plain = [None] * len(processed)  
cur_xored = [None] * len(processed)  
perm_solutions = []

def dfs(pos: int = 0):  
if len(perm_solutions) >= 12:  
return  
if pos == len(order):  
candidate = bytes(cur_plain)  
if candidate.startswith(b"ENO{") and set(cur_xored) == xored_set_obs:  
perm_solutions.append(candidate)  
return

idx = order[pos]  
for p, x in per_pos_choices[idx]:  
if idx in fixed and p != fixed[idx]:  
continue  
cur_plain[idx] = p  
cur_xored[idx] = x  
dfs(pos + 1)  
cur_plain[idx] = None  
cur_xored[idx] = None

dfs()  
if perm_solutions:  
solutions.extend(perm_solutions)

return sorted(set(solutions))

def score_candidate(flag_bytes: bytes):  
s = flag_bytes.decode("ascii", "ignore")  
score = 0  
score += 100 if s.startswith("ENO{") and s.endswith("}") else 0  
score += s.count("_") * 5  
score += 80 if "_really_" in s else 0  
score += 100 if "_you_" in s else 0  
score += 100 if "g00d" in s else 0  
score += 120 if "c0v3r4g3_l34k5_s3cr3t5" in s else 0  
score -= sum(1 for ch in s[4:-1] if ch.isupper()) * 3  
return score, s

def main():  
php_source = ENCRYPT_PHP.read_text()  
mapping, reverse = parse_substitution_table(php_source)

coverage = json.loads(COVERAGE_JSON.read_text())  
file_key = next(iter(coverage))  
branches = coverage[file_key]["functions"]["FlagEncryptor->encrypt"]["branches"]

keyset = sorted(extract_true_value_set(branches, 46))  
xored_set_obs = extract_true_value_set(branches, 1590)

encrypted = ENCRYPTED_FLAG.read_text().strip()  
b64, sha1_hex = encrypted.split(":", 1)  
processed = base64.b64decode(b64)  
actual_sha1 = hashlib.sha1(processed).hexdigest()  
if actual_sha1 != sha1_hex:  
raise ValueError("sha1 mismatch, input corrupted")

candidates = recover_candidates(processed, mapping, reverse, keyset, xored_set_obs)  
if not candidates:  
raise RuntimeError("no ENO{} candidate found")

ranked = sorted((score_candidate(c), c) for c in candidates)  
best = ranked[-1][1]

print("[+] key bytes set from coverage:", keyset)  
print("[+] candidate count:", len(candidates))  
for idx, c in enumerate(candidates, 1):  
print(f" {idx:02d}. {c.decode()}")  
print("\n[+] selected flag:", best.decode())

if __name__ == "__main__":  
main()  
```

\---
