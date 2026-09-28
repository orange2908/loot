---
title: "Bada - Crypto CTF 2024"
category: "pwn"
subcategory: "symbolic-execution"
type: "writeup"
tags: ["pwn", "math", "factor", "pwntools", "z3", "bada", "symbolic-execution", "crypto-ctf", "crypto-ctf-2024", "2024", "ctf-writeup"]
summary: "The Bada equation contains an undetermined function."
source:
  name: "CTFtime writeup #39188"
  url: "https://ctftime.org/writeup/39188"
original_source: "https://lov2.netlify.app/cryptoctf2024_wp/"
ctf:
  name: "Crypto CTF 2024"
  year: 2024
  challenge: "Bada"
---

## Metadata

- **CTF:** Crypto CTF 2024
- **Task:** Bada
- **Author team:** ③籍贯
- **CTFtime tags:** math, factor, pwntools
- **CTFtime:** <https://ctftime.org/writeup/39188>
- **Original writeup:** <https://lov2.netlify.app/cryptoctf2024_wp/>

---
## Bada

Points: 90

Solve: 51

Difficulty: Medium ?

### 题面

Bada  
The Bada equation contains an undetermined function. By closely examining how this equation behaves, you may be able to discover the concealed flag.

nc [00.cr.yp.toc.tf](http://00.cr.yp.toc.tf) 17113  
Note: There is no file to download in this challenge!

### 尝试交互

```shell  
> nc [00.cr.yp.toc.tf](http://00.cr.yp.toc.tf) 17113  
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓  
┃ Hey! It's time to solve the equation of a function f: N x N -> Z. ┃  
┃ Function f has given certain conditions. In each step, solve the ┃  
┃ equation f(x, y) = z with the given value of z. We know f(a+1, b) = ┃  
┃ f(a, b) + a, and f(a, b+1) = f(a, b) - b, for every `a' and `b'. ┃  
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛  
┃ We know: f(1, 1) = -444045537086 and f(x, y) = 202500187503  
┃ Please send x, y separated by comma:

```

### 概述

通过将 $f(x, y) - f(1, 1) = n$ 转换成一个因式分解的问题，然后用这种分解来求解 $x$ 和 $y$ 的值。可以有效利用 $n$ 的因子来找到可能的 $x$ 和 $y$

### 方法详解

1\. **设置**:  
$$  
2n = (x - y)(x + y - 1)  
$$  
通过设置 $2n = ab$，其中 $a = x - y$ 和 $b = x + y - 1$，可以求解 $x$ 和 $y$。

2\. **求解 $x$ 和 $y$**:  
$$  
x = \frac{a + b + 1}{2}, \quad y = \frac{b - a + 1}{2}  
$$

3\. **条件检查**:  
\- $a + b + 1$ 应为偶数，以确保 $x$ 是整数。  
\- $b - a + 1$ 也应为偶数，以确保 $y$ 是整数。  
\- $x \geq 1$ 和 $y \geq 1$ 确保值在定义域内。

### 单次询问/求解

```python  
def find_xy(n):  
solutions = []  
# 遍历可能的因子 a, b，其中 2n = a * b  
for a in range(1, int(2*n**0.5) + 1):  
if (2*n) % a == 0:  
b = (2*n) // a  
# 检查是否满足 a + b + 1 和 b - a + 1 都是偶数  
if (a + b + 1) % 2 == 0 and (b - a + 1) % 2 == 0:  
x = (a + b + 1) // 2  
y = (b - a + 1) // 2  
if x >= 1 and y >= 1:  
solutions.append((x, y))  
return solutions

# 设置 f(1, 1) 和目标 f(x, y)  
f_1_1 = -793336362005  
target_f_xy = 157252801734

# 计算 n  
n = target_f_xy - f_1_1

# 查找符合条件的 x, y 对  
result = find_xy(n)  
if result:  
print(f"Found solutions: {result}")  
else:  
print("No solution found.")  
```

提交后发现还有下一个 level, 于是利用 Pwntools 写交互脚本

### Exploit

```python  
from pwn import *  
from z3 import *

# 连接到挑战服务器  
context.log_level = "DEBUG"  
host, port = "[01.cr.yp.toc.tf](http://01.cr.yp.toc.tf)", 17113  
conn = remote(host, port)

while True:

# 读取数据直到 'f(1, 1) ='  
response = conn.recvuntil(b'f(1, 1) = ').decode()  
print(response)

# 接着读取f(1, 1)的值直到' and f(x, y) = '  
response += conn.recvuntil(b' and f(x, y) = ').decode()  
# 从响应中提取f(1, 1)的值  
initial_value = int(response.split('f(1, 1) = ')[1].split(' ')[0])  
print(f"[+] f(1, 1) = {initial_value}")

# 继续接收数据获取f(x, y)的值  
remaining_data = conn.recvline().strip().decode()  
target_value = int(remaining_data)  
print(f"[+] f(x, y) = {target_value}")

def find_xy(n):  
solutions = []  
# 遍历可能的因子 a, b，其中 2n = a * b  
for a in range(1, int(2*n**0.5) + 1):  
if (2*n) % a == 0:  
b = (2*n) // a  
# 检查是否满足 a + b + 1 和 b - a + 1 都是偶数  
if (a + b + 1) % 2 == 0 and (b - a + 1) % 2 == 0:  
x = (a + b + 1) // 2  
y = (b - a + 1) // 2  
if x >= 1 and y >= 1:  
solutions.append((x, y))  
break  
return solutions

# 设置 f(1, 1) 和目标 f(x, y)  
# f_1_1 = -793336362005  
# target_f_xy = 157252801734  
f_1_1 = initial_value  
target_f_xy = target_value

# 计算 n  
n = target_f_xy - f_1_1

# 查找符合条件的 x, y 对  
result = find_xy(n)  
if result:  
print(f"[Y] Found solutions: {result}")  
else:  
print("[N] No solution found.")

for x, y in result:  
conn.sendline(f"{x},{y}")  
break  
print(f"[+] Sent: {x},{y}")

# CCTF{BADA_iZ_4_K0r3An_5!ngeR!!}  
"""  
[DEBUG] Received 0x63 bytes:  
00000000 e2 94 83 20 43 6f 6e 67 72 61 74 75 6c 61 74 69 │··· │Cong│ratu│lati│  
00000010 6f 6e 21 20 59 6f 75 20 67 6f 74 20 74 68 65 20 │on! │You │got │the │  
00000020 66 6c 61 67 21 0a e2 94 83 20 66 6c 61 67 20 3d │flag│!···│· fl│ag =│  
00000030 20 62 27 43 43 54 46 7b 42 41 44 41 5f 69 5a 5f │ b'C│CTF{│BADA│_iZ_│  
00000040 34 5f 4b 30 72 33 41 6e 5f 35 21 6e 67 65 52 21 │4_K0│r3An│_5!n│geR!│  
00000050 21 7d 27 0a e2 94 83 20 45 78 69 74 69 6e 67 2e │!}'·│··· │Exit│ing.│  
00000060 2e 2e 0a │..·│  
00000063  
"""  
```
