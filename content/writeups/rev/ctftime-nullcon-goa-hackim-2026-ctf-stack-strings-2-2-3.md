---
title: "stack strings 2 - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "stack-strings", "reverse", "xor", "stack", "strings", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- <https://ctf.nullcon.net/files/0cc73871ab190a1b030fd1aae9a55bf2/stackstringshard?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo5OX0.aYqlNw.wlBT1dR0ofciyKVrk6vPluSVes>"
source:
  name: "CTFtime writeup #40556"
  url: "https://ctftime.org/writeup/40556"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "stack strings 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** stack strings 2
- **Author team:** 正规子群.AI
- **CTFtime tags:** stack-strings, reverse
- **CTFtime:** <https://ctftime.org/writeup/40556>

---
## 129 stack strings 2

\- Category: `rev`  
\- Value: `50`  
\- Solves: `172`  
\- Solved by me: `True`  
\- Local directory: `N/A`

### 题目描述  
> Nothing to see here part 2

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/0cc73871ab190a1b030fd1aae9a55bf2/stackstrings_hard?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo5OX0.aYqlNw.wlBT1dR0ofciyKVr_k6vPluSVes>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
Flag verification passed!  
Flag: ENO{W0W_D1D_1_JU5T_UNLUCK_4_N3W_SK1LL???}

Compared to the medium version, the hard version introduces three major increases in complexity:

1.Substitution (out-of-order access) — Instead of reading input[i] sequentially, the program uses the hash value hash1 as an index and reads input[hash1], effectively applying a permutation to the input  
2.Accumulator mechanism — Introduces the bl register as a chained accumulator. Each comparison result is computed as  
bl = rol8(prev, 1) + (hash3 ^ input[idx]),  
making the current state depend on the previous round and forming a data dependency chain  
3.Dual hash streams — Two different hash values are derived from the same edx register (with XOR constants 0xec8804a0 and 0x19e0463b). One is used to compute the input read index, and the other to compute the expected value

[solve.py](http://solve.py):  
```  
#!/usr/bin/env python3

import struct  
with open("stackstrings_hard", "rb") as f:  
binary = f.read()

# Buffer data at VA 0x20e0, size 0xfa  
buf = bytearray(binary[0x20e0:0x20e0 + 0xfa])

# === Decrypt first prompt buf[0..0x40] ===  
buf[0] = 0x3d  
for i in range(16):  
buf[1 + i] ^= binary[0x2010 + i]  
buf[0x11 + i] ^= binary[0x2020 + i]  
buf[0x21 + i] ^= binary[0x2030 + i]  
buf[0x31 + i] ^= binary[0x2040 + i]  
prompt1 = bytes(buf[0:0x41])  
print(f"Prompt 1: {prompt1}")

# === Re-XOR buf[0..0x40] ===  
for i in range(16):  
buf[0 + i] ^= binary[0x2050 + i]  
buf[0x10 + i] ^= binary[0x2060 + i]  
buf[0x20 + i] ^= binary[0x2070 + i]  
buf[0x30 + i] ^= binary[0x2080 + i]  
buf[0x40] ^= 0x93

# === Decrypt second prompt buf[0x41..0x62] ===  
for i in range(16):  
buf[0x41 + i] ^= binary[0x2090 + i]  
buf[0x51 + i] ^= binary[0x20a0 + i]  
buf[0x61] ^= 0x34  
buf[0x62] ^= 0xf7

prompt2 = bytes(buf[0x41:0x41 + 0x22])  
print(f"Prompt 2: {prompt2}")

# === Re-XOR buf[0x41..0x62] ===  
for i in range(16):  
buf[0x41 + i] ^= binary[0x2090 + i]  
buf[0x51 + i] ^= binary[0x20a0 + i]  
buf[0x61] ^= 0x34  
buf[0x62] ^= 0xf7

# === Extract keys ===  
expected_len = buf[0xf4] ^ 0xa7  
key_b1 = buf[0xf5] ^ 0x3a  
key_b2 = buf[0xf6] ^ 0xd3  
key_b3 = buf[0xf7] ^ 0x4b  
key_b4 = buf[0xf8] ^ 0x13  
r15 = (key_b4 << 24) | (key_b3 << 16) | (key_b2 << 8) | key_b1  
r13_init = (buf[0xf9] ^ 0x77) & 0xff

print(f"Expected length: {expected_len}")  
print(f"r15: 0x{r15:08x}")  
print(f"r13_init: 0x{r13_init:02x}")

# Cipher tables  
table_a2 = buf[0xa2:0xa2 + expected_len] # used to compute hash1 (index into input)  
table_cb = buf[0xcb:0xcb + expected_len] # used to compute expected comparison value

def rol32(val, n):

n = n & 31

val &= 0xffffffff

return ((val << n) | (val >> (32 - n))) & 0xffffffff

def rol8(val, n):

n = n & 7

val &= 0xff

return ((val << n) | (val >> (8 - n))) & 0xff

# === Solve ===

# Loop state

edx = 0x9e3779b9

r10 = 0xa97288ed

r9 = 0

r13 = r13_init # accumulator carried across iterations

flag = [0] * 256

print("\nSolving each iteration:")

for i in range(expected_len):

bl = r13 & 0xff # bl = r13 from previous iteration

cl = i & 7

# --- hash1: compute index into input ---

esi = (edx ^ 0xec8804a0) & 0xffffffff

esi = rol32(esi, cl)

temp = ((esi >> 16) ^ esi) & 0xffffffff

hash1_low = ((temp >> 8) ^ temp) & 0xff

hash1_low ^= table_a2[i]

index = hash1_low

# --- hash2: compute expected comparison value ---

eax = (edx ^ 0x19e0463b) & 0xffffffff

eax = rol32(eax, cl)

temp = ((eax >> 16) ^ eax) & 0xffffffff

expected = ((temp >> 8) ^ temp) & 0xff

expected ^= table_cb[i]

# --- hash3: from r10 and r15 ---

esi3 = (r10 ^ r15) & 0xffffffff

cl3 = r9 & 7

esi3 = rol32(esi3, cl3)

temp3 = ((esi3 >> 15) ^ esi3) & 0xffffffff

hash3_low = ((temp3 >> 7) ^ temp3) & 0xff

# --- Equation ---

# bl_new = rol8(bl, 1) + (hash3_low ^ input[index])

# bl_new must equal expected

# => input[index] = hash3_low ^ ((expected - rol8(bl, 1)) & 0xff)

bl_rot = rol8(bl, 1)

diff = (expected - bl_rot) & 0xff

input_byte = hash3_low ^ diff

flag[index] = input_byte

r13 = input_byte # r13 for next iteration = current input byte

ch = chr(input_byte) if 32 <= input_byte < 127 else '?'

print(f" i={i:2d}: index={index:3d} (0x{index:02x}), byte=0x{input_byte:02x} '{ch}'")

# Update loop variables

r9 = (r9 + 3) & 0xffffffff

r10 = (r10 + 0x85ebca6b) & 0xffffffff

edx = (edx + 0x9e3779b9) & 0xffffffff

flag_str = bytes(flag[:expected_len])

print(f"\nFlag: {flag_str}")

# === Also decrypt messages ===

# Wrong message at buf[0x7f], 0x23 bytes

wrong_buf = bytearray(buf)

for i in range(16):

wrong_buf[0x7f + i] ^= binary[0x20b0 + i]

wrong_buf[0x8f + i] ^= binary[0x20c0 + i]

wrong_buf[0x9f] ^= 0x88

wrong_buf[0xa0] ^= 0x8e

wrong_buf[0xa1] ^= 0xe5

print(f"Wrong msg: {bytes(wrong_buf[0x7f:0x7f+0x23])}")

# Correct message at buf[0x63], 0x1c bytes

correct_buf = bytearray(buf)

for i in range(16):

correct_buf[0x63 + i] ^= binary[0x20d0 + i]

# Additional XOR loop for buf[0x73..0x7e] 12 bytes

eax_c = 0x81af1549

for j in range(12):

cl_c = (j + 0x10) & 7

esi_c = (eax_c ^ 0x76d51373) & 0xffffffff

esi_c = rol32(esi_c, cl_c)

temp_c = ((esi_c >> 16) ^ esi_c) & 0xffffffff

key_c = ((temp_c >> 8) ^ temp_c) & 0xff

correct_buf[0x73 + j] ^= key_c

eax_c = (eax_c + 0x9e3779b9) & 0xffffffff

print(f"Correct msg: {bytes(correct_buf[0x63:0x63+0x1c])}")  
```

# pwn

### Exploit  
\- Exploit 代码未在本地标准 `solution/` 目录找到，可能嵌在外部 WP 文本中。  
\- 已在上方 WP 小节插入相关文本来源，可继续抽取为独立脚本。

\---
