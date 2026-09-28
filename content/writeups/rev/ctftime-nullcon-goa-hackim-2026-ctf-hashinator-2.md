---
title: "Hashinator - Nullcon Goa HackIM 2026 CTF"
category: "rev"
subcategory: "stack"
type: "writeup"
tags: ["rev", "hash", "reverse", "inversion", "canary", "radare2", "lsb", "subprocess", "regex", "objdump", "stack", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: rev/Hashinator"
source:
  name: "CTFtime writeup #40553"
  url: "https://ctftime.org/writeup/40553"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Hashinator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Hashinator
- **Author team:** 正规子群.AI
- **CTFtime tags:** hash, reverse, inversion
- **CTFtime:** <https://ctftime.org/writeup/40553>

---
## 107 Hashinator

\- Category: `rev`  
\- Value: `89`  
\- Solves: `138`  
\- Solved by me: `True`  
\- Local directory: `rev/Hashinator`

### 题目描述  
> We've found this binary in an super old backup of a super old system. It outputs some hashes, but maybe there's more to it?  
>  
> Author: @gehaxelt

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/f520d3e1a23e37d48c89e7566860c726/public.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo4Mn0.aYqlOQ.sYZ-2nBAxEOAEomOx6NIGdYNFf0>`

### 内存布局  
\- Binary path: `rev/Hashinator/task/challenge_final`  
\- File type: `ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=3b007774aade898538942f398d7a5062f94a5545, for GNU/Linux 4.4.0, with debug_info, not stripped`  
\- arch: `x86`  
\- bits: `64`  
\- class: `ELF64`  
\- bintype: `elf`  
\- machine: `AMD x86-64 architecture`  
\- endian: `little`  
\- os: `linux`  
\- pic: `false`  
\- nx: `true`  
\- canary: `true`  
\- relro: `partial`  
\- stripped: `false`  
\- baddr: `0x400000`

```text  
nth paddr size vaddr vsize perm flags type name  
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――  
0 0x00000000 0x0 0x00000000 0x0 ---- 0x0 NULL  
1 0x000002e0 0x20 0x004002e0 0x20 -r-- 0x2 NOTE .note.gnu.property  
2 0x00000300 0x24 0x00400300 0x24 -r-- 0x2 NOTE .note.gnu.build-id  
3 0x00000328 0x3c0 0x00400328 0x3c0 -r-- 0x42 RELA .rela.plt  
4 0x00001000 0x1b 0x00401000 0x1b -r-x 0x6 PROGBITS .init  
5 0x00001020 0xe0 0x00401020 0xe0 -r-x 0x6 PROGBITS .plt  
6 0x00001100 0xc4f89 0x00401100 0xc4f89 -r-x 0x6 PROGBITS .text  
7 0x000c608c 0xd 0x004c608c 0xd -r-x 0x6 PROGBITS .fini  
8 0x000c7000 0x532bc 0x004c7000 0x532bc -r-- 0x2 PROGBITS .rodata  
9 0x0011a2bc 0x1 0x0051a2bc 0x1 -r-- 0x2 PROGBITS .stapsdt.base  
10 0x0011a2c0 0x60 0x0051a2c0 0x60 -r-- 0x12 PROGBITS rodata.cst32  
11 0x0011a320 0x1251c 0x0051a320 0x1251c -r-- 0x2 PROGBITS .eh_frame  
12 0x0012c840 0xa989 0x0052c840 0xa989 -r-- 0x2 ---- .sframe  
13 0x0013b4f3 0x312 0x0053b4f3 0x312 -r-- 0x2 PROGBITS .gcc_except_table  
14 0x0013b808 0x20 0x0053b808 0x20 -r-- 0x2 NOTE .note.ABI-tag  
15 0x0013bc50 0x30 0x0053cc50 0x30 -rw- 0x403 PROGBITS .tdata  
16 0x0013bc80 0x0 0x0053cc80 0x28 -rw- 0x403 NOBITS .tbss  
17 0x0013bc80 0x10 0x0053cc80 0x10 -rw- 0x3 INIT_ARRAY .init_array  
18 0x0013bc90 0x10 0x0053cc90 0x10 -rw- 0x3 FINI_ARRAY .fini_array  
19 0x0013bca0 0x4208 0x0053cca0 0x4208 -rw- 0x3 PROGBITS .data.rel.ro  
20 0x0013fea8 0x140 0x00540ea8 0x140 -rw- 0x3 PROGBITS .got  
21 0x0013ffe8 0xf8 0x00540fe8 0xf8 -rw- 0x3 PROGBITS .got.plt  
22 0x001400e0 0x1c70 0x005410e0 0x1c70 -rw- 0x3 PROGBITS .data  
23 0x00141d50 0x0 0x00542d60 0x25848 -rw- 0x3 NOBITS .bss  
24 0x00141d50 0x48 0x00000000 0x48 ---- 0x30 PROGBITS .comment  
25 0x00141d98 0x1778 0x00000000 0x1778 ---- 0x0 NOTE .note.stapsdt  
26 0x00143510 0x570 0x00000000 0x570 ---- 0x0 PROGBITS .debug_aranges  
27 0x00143a80 0x4d669 0x00000000 0x4d669 ---- 0x0 PROGBITS .debug_info  
28 0x001910e9 0x5b75 0x00000000 0x5b75 ---- 0x0 PROGBITS .debug_abbrev  
29 0x00196c5e 0x127b2 0x00000000 0x127b2 ---- 0x0 PROGBITS .debug_line  
```

### WP  
# Hashinator Writeup

\---

## 题目信息

\- 题目：`Hashinator`  
\- 类型：Reverse  
\- 附件：`task/challenge_final`, `task/OUTPUT.txt`  
\- flag 格式：`ENO{...}`

补充：从 DWARF 中可见编译路径包含 `nullcon-ctf-goa-2026`，可推测比赛为 Nullcon 相关场次。

\---

## 初步静态分析

先只做静态分析（符合 Reverse 要求），关键命令如下：

```bash  
file task/challenge_final  
nm -an task/challenge_final | head  
objdump -d task/challenge_final --start-address=0x403240 --stop-address=0x403380  
r2 -q -A task/challenge_final  
dwarfdump task/challenge_final  
objdump -d -l task/challenge_final --start-address=0x404a00 --stop-address=0x404c40  
```

得到的关键结论：

1\. `challenge_final` 是 `ELF 64-bit x86-64`，静态链接，未 strip，且带调试信息。  
2\. 主函数 `main` 会调用 `init_Achallenge_Afinal`，再跳转执行对象系统入口。  
3\. 符号和 DWARF 显示该程序由 OCS/Nim 风格中间层生成（如 `___Achallenge_Afinal_3`）。  
4\. `OUTPUT.txt` 中有 55 行 32 位十六进制串（看起来像 md5 风格输出）。

\---

## 关键逆向观察

在无法直接本机执行 Linux x86_64 ELF 的前提下，先从静态信息定位行为，再结合可控输入做黑盒验证。

### 1 输入长度限制

对二进制喂短输入会报错：

```text  
Error: Input must be at least 15 characters long  
```

说明程序要求 $|s| \ge 15$。

### 2 输出行数规律

输入长度为 15 时，输出 16 行哈希；长度为 20 时，输出 21 行哈希。

于是有关系：

$$  
\text{lines} = |s| + 1  
$$

### 3 前缀决定前缀哈希

构造两个输入：

\- `ABCDEFGHIJXXXXXXXXXX`  
\- `ABCDEFGHIJYYYYYYYYYY`

对比输出可见前 11 行完全一致，后续才分叉。说明第 $i$ 行只依赖前 $i$ 个字符（以及固定初始状态）。

可以抽象为：

$$  
H_0 = C,\quad H_i = F(H_{i-1}, s_i)  
$$

其中 $C$ 是固定初值，$F$ 是程序内部状态变换。

\---

## 解题思路最终采用

利用“前缀一致 -> 前缀哈希一致”这个性质，做逐字符恢复。

设目标哈希序列为 `target[0..n]`（来自 `OUTPUT.txt`）。

已知当前前缀 `p`，枚举候选字符 `ch`：

1\. 构造测试串 `trial = p + ch + filler`，其中 `filler` 只用于补足最小长度 15。  
2\. 跑程序得到输出 `out`。  
3\. 若 `out[:len(trial)+1] == target[:len(trial)+1]`，则 `ch` 是当前位置正确字符。

逐位推进直到长度达到 $n$，最终得到完整明文。

\---

## 失败与修正记录

1\. **第一次脚本跑得很慢**：初始候选集用全可打印字符，且未做前缀续跑，整体耗时高。  
2\. **一次中断后继续**：改为支持从已知前缀继续恢复。  
3\. **字符集问题**：只用字母数字和 `_{} ` 时，在后段失败；补上回退到全可打印字符后成功（题目确实包含 `!`）。  
4\. **`OUTPUT.txt` 解析细节**：文件首行包含命令行回显，最终用正则仅提取 `[0-9a-f]{32}` 行。

\---

## 关键汇编/伪代码片段

从 `objdump -d -l` 可见主逻辑位于：

\- `___Achallenge_Afinal_3` at `0x404a00`（大函数，包含核心流程）  
\- `_Achallenge_Afinal_26` at `0x408fc0`（对象/状态拼接路径）

概念伪代码（根据黑盒行为归纳）：

```c  
read input s;  
if (len(s) < 15) error;  
state = CONST;  
print(hash(state));  
for (i = 0; i < len(s); i++) {  
state = Mix(state, s[i]);  
print(hash(state));  
}  
```

这与观测到的“输出长度=输入长度+1”和“前缀稳定性”一致。

\---

## 解题脚本

脚本路径：`solution/[solution.py](http://solution.py)`

用途：

1\. 从 `task/OUTPUT.txt` 读取目标哈希序列。  
2\. 逐位恢复 flag（默认前缀 `ENO{`）。  
3\. 用恢复出的完整字符串再次运行程序，做全量哈希比对。

典型运行（macOS + OrbStack Linux）：

```bash  
orb bash -lc 'cd rev/Hashinator && python3 -u solution/[solution.py](http://solution.py)'  
```

\---

## 最终结果

```text  
ENO{MD2_1S_S00_0ld_B3tter_Implement_S0m3Th1ng_ElsE!!}  
```

验证结果：`match_output=True`（与 `task/OUTPUT.txt` 全量一致）。

### Exploit  
#### rev/Hashinator/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
from __future__ import annotations

import argparse  
import re  
import string  
import subprocess  
from pathlib import Path

def run_target(bin_path: Path, data: str, timeout_sec: float) -> list[str]:  
p = subprocess.run(  
[str(bin_path)],  
input=data.encode(),  
stdout=subprocess.PIPE,  
stderr=subprocess.PIPE,  
check=False,  
timeout=timeout_sec,  
)  
out = p.stdout.decode(errors="replace").splitlines()  
return [line.strip() for line in out if line.strip()]

def recover_flag(  
bin_path: Path,  
target_hashes: list[str],  
known_prefix: str,  
charset: str,  
fallback_charset: str,  
timeout_sec: float,  
) -> str:  
# output count = len(input) + 1 (line 0 is a fixed initial state)  
flag_len = len(target_hashes) - 1  
recovered = known_prefix

# Validate initial prefix, if provided.  
if recovered:  
filler = "A" * max(0, 15 - len(recovered))  
out = run_target(bin_path, recovered + filler, timeout_sec)  
need = len(recovered) + 1  
if out[:need] != target_hashes[:need]:  
raise RuntimeError("已知前缀与目标哈希不匹配，请检查前缀或样本。")

while len(recovered) < flag_len:  
pos = len(recovered) + 1 # character position, 1-based  
found: list[str] = []

def scan(candidate_set: str) -> list[str]:  
hits: list[str] = []  
for ch in candidate_set:  
trial = recovered + ch  
filler = "A" * max(0, 15 - len(trial))  
out = run_target(bin_path, trial + filler, timeout_sec)  
need = len(trial) + 1  
if len(out) < need:  
continue  
if out[:need] == target_hashes[:need]:  
hits.append(ch)  
return hits

found = scan(charset)  
if len(found) == 0:  
extra = "".join(ch for ch in fallback_charset if ch not in charset)  
if extra:  
found = scan(extra)

if len(found) == 0:  
raise RuntimeError(f"位置 {pos} 未找到可行字符，当前前缀: {recovered!r}")  
if len(found) > 1:  
raise RuntimeError(  
f"位置 {pos} 出现多个候选 {found!r}，当前前缀: {recovered!r}，需要扩展回溯逻辑。"  
)

recovered += found[0]  
print(f"[+] pos={pos:02d} -> {found[0]!r} | prefix={recovered}")

return recovered

def verify_full(bin_path: Path, candidate: str, target_hashes: list[str], timeout_sec: float) -> bool:  
out = run_target(bin_path, candidate, timeout_sec)  
return out == target_hashes

def main() -> None:  
parser = argparse.ArgumentParser(description="Hashinator solver")  
parser.add_argument("--bin", type=Path, default=Path("task/challenge_final"))  
parser.add_argument("--output", type=Path, default=Path("task/OUTPUT.txt"))  
parser.add_argument("--prefix", default="ENO{")  
parser.add_argument("--timeout", type=float, default=3.0)  
parser.add_argument(  
"--charset",  
default=string.ascii_letters + string.digits + "_{}",  
help="首选候选字符集合，默认常见 flag 字符",  
)  
parser.add_argument(  
"--fallback-charset",  
default="".join(chr(i) for i in range(32, 127)),  
help="首选集合未命中时的回退集合，默认 ASCII 可打印字符 [0x20,0x7e]",  
)  
args = parser.parse_args()

target_hashes = [line.strip() for line in args.output.read_text().splitlines() if re.fullmatch(r"[0-9a-f]{32}", line.strip())]  
if not target_hashes:  
raise RuntimeError("OUTPUT.txt 为空")

flag = recover_flag(args.bin, target_hashes, args.prefix, args.charset, args.fallback_charset, args.timeout)  
ok = verify_full(args.bin, flag, target_hashes, args.timeout)

print("\n=== RESULT ===")  
print(flag)  
print(f"match_output={ok}")

if __name__ == "__main__":  
main()  
```

\---
