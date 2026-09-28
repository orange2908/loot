---
title: "stack strings 1 - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "stack-strings", "reverse", "xor", "stack", "strings", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "\\- <https://ctf.nullcon.net/files/74015188b5cea699e1791416ee516952/stackstringsmed?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo5OH0.aYqlNg.BLewSBezGUXVFL5U66snMH6w1ek>"
source:
  name: "CTFtime writeup #40557"
  url: "https://ctftime.org/writeup/40557"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "stack strings 1"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** stack strings 1
- **Author team:** 正规子群.AI
- **CTFtime tags:** stack-strings, reverse
- **CTFtime:** <https://ctftime.org/writeup/40557>

---
## 128 stack strings 1

\- Category: `rev`  
\- Value: `50`  
\- Solves: `206`  
\- Solved by me: `True`  
\- Local directory: `N/A`

### 题目描述  
> Nothing to see here part 1

### 连接信息  
\- 无

### 附件下载地址  
\- `<https://ctf.nullcon.net/files/74015188b5cea699e1791416ee516952/stackstrings_med?token=eyJ1c2VyX2lkIjo1MDYyLCJ0ZWFtX2lkIjoyMzEyLCJmaWxlX2lkIjo5OH0.aYqlNg.BLewSBezGUXVFL5U66snMH6w1ek>`

### 内存布局  
\- 暂无可解析二进制 或 本题主要是非二进制方向

### WP  
Flag found!  
Flag: ENO{1_L0V3_R3V3R51NG_5T4CK_5TR1NG5}

Program logic analysis:  
1.Memory allocation and encrypted data copy — Uses mmap to allocate 0xbd bytes and copies encrypted data from the .rodata section  
2.XOR decryption of stack strings — Decrypts prompt strings through multiple rounds of XOR operations (e.g., "Bytebrew Bazaar Receipt Printer" and "Enter member code")  
3.Read user input — Reads input character by character, expecting a length of 35  
4.Custom password verification — Applies two parallel hash streams (based on constants 0x9e3779b9 and 0xa97288ed, involving rotations/shifts/XOR operations) to encrypt and compare the input  
5.Output result — Displays "ACCESS GRANTED" if matched, otherwise "ACCESS DENIED"

[solve.py](http://solve.py):  
```  
#!/usr/bin/env python3  
import struct  
with open("stackstrings_med", "rb") as f:  
binary = f.read()  
# .rodata is at VA 0x2000, file offset 0x2000  
# Buffer data copied from VA 0x20d0 file offset 0x20d0, size 0xbd  
buf = bytearray(binary[0x20d0:0x20d0 + 0xbd])  
# === Decrypt first prompt buf[0..0x47] ===  
buf[0] = 0x3d

# XOR keys for buf[1..64]  
key_2010 = binary[0x2010:0x2020]  
key_2020 = binary[0x2020:0x2030]  
key_2030 = binary[0x2030:0x2040]  
key_2040 = binary[0x2040:0x2050]

for i in range(16):  
buf[1 + i] ^= key_2010[i]  
buf[0x11 + i] ^= key_2020[i]  
buf[0x21 + i] ^= key_2030[i]  
buf[0x31 + i] ^= key_2040[i]

buf[0x41] ^= 0x5d  
buf[0x42] ^= 0x9a  
buf[0x43] ^= 0x89  
buf[0x44] ^= 0xeb  
buf[0x45] ^= 0x89  
buf[0x46] ^= 0x3d  
buf[0x47] ^= 0x95

prompt1 = bytes(buf[0:0x48])  
print(f"Prompt 1: {prompt1}")

# === Re-XOR buf[0..0x47] restore/transform for next step ===  
key_2050 = binary[0x2050:0x2060]  
key_2060 = binary[0x2060:0x2070]  
key_2070 = binary[0x2070:0x2080]  
key_2080 = binary[0x2080:0x2090]

for i in range(16):  
buf[0 + i] ^= key_2050[i]  
buf[0x10 + i] ^= key_2060[i]  
buf[0x20 + i] ^= key_2070[i]  
buf[0x30 + i] ^= key_2080[i]

buf[0x40] ^= 0xdd  
buf[0x41] ^= 0x5d  
buf[0x42] ^= 0x9a  
buf[0x43] ^= 0x89  
buf[0x44] ^= 0xeb  
buf[0x45] ^= 0x89  
buf[0x46] ^= 0x3d  
buf[0x47] ^= 0x95

# === Decrypt second prompt buf[0x48..0x5c] ===  
key_2090 = binary[0x2090:0x20a0]  
for i in range(16):  
buf[0x48 + i] ^= key_2090[i]

buf[0x58] ^= 0xf8  
buf[0x59] ^= 0xfd  
buf[0x5a] ^= 0x66  
buf[0x5b] ^= 0xab  
buf[0x5c] ^= 0xd2

prompt2 = bytes(buf[0x48:0x48 + 0x15])  
print(f"Prompt 2: {prompt2}")

# === Re-XOR buf[0x48..0x5c] ===  
for i in range(16):  
buf[0x48 + i] ^= key_2090[i]  
buf[0x58] ^= 0xf8  
buf[0x59] ^= 0xfd  
buf[0x5a] ^= 0x66  
buf[0x5b] ^= 0xab  
buf[0x5c] ^= 0xd2

# === Compute expected length and key ===  
expected_len = buf[0xb8] ^ 0x36  
key_b1 = buf[0xb9] ^ 0x19  
key_b2 = buf[0xba] ^ 0x95  
key_b3 = buf[0xbb] ^ 0xc7  
key_b4 = buf[0xbc] ^ 0x0a

r15 = (key_b4 << 24) | (key_b3 << 16) | (key_b2 << 8) | key_b1  
print(f"Expected length: {expected_len}")  
print(f"r15 key: 0x{r15:08x}")

# === Cipher data at buf[0x95..0x95+expected_len] ===

cipher_data = buf[0x95:0x95 + expected_len]

def rol32(val, n):  
n = n & 31  
val &= 0xffffffff  
return ((val << n) | (val >> (32 - n))) & 0xffffffff

# === Solve for input ===  
eax = 0xa97288ed  
ebx = 0x9e3779b9  
r9 = 0

flag = []  
for i in range(expected_len):  
# hash_b from ebx  
esi = (ebx ^ 0xc19ef49e) & 0xffffffff  
esi = rol32(esi, i & 7)  
temp = ((esi >> 16) ^ esi) & 0xffffffff  
hash_b_low = ((temp >> 8) ^ temp) & 0xff  
hash_b_low ^= cipher_data[i]

# hash_a from eax  
edx = (eax ^ r15) & 0xffffffff  
edx = rol32(edx, r9 & 7)  
temp = ((edx >> 15) ^ edx) & 0xffffffff  
hash_a_low = ((temp >> 7) ^ temp) & 0xff

# We need: hash_a_low ^ input[i] == hash_b_low  
# So: input[i] = hash_a_low ^ hash_b_low  
ch = hash_a_low ^ hash_b_low  
flag.append(ch)

r9 = (r9 + 3) & 0xffffffff  
eax = (eax + 0x85ebca6b) & 0xffffffff  
ebx = (ebx + 0x9e3779b9) & 0xffffffff

flag_str = bytes(flag)  
print(f"Flag: {flag_str}")

# === Also decrypt the "correct" and "wrong" messages ===  
# Wrong message at buf[0x7e], 0x17 bytes  
wrong_buf = bytearray(buf)  
key_20a0 = binary[0x20a0:0x20b0]  
for i in range(16):  
wrong_buf[0x7e + i] ^= key_20a0[i]  
wrong_buf[0x8e] ^= 0x7f  
wrong_buf[0x8f] ^= 0xf2  
wrong_buf[0x90] ^= 0x78  
wrong_buf[0x91] ^= 0x97  
wrong_buf[0x92] ^= 0xaa  
wrong_buf[0x93] ^= 0x58  
wrong_buf[0x94] ^= 0x2c  
print(f"Wrong msg: {bytes(wrong_buf[0x7e:0x7e+0x17])}")

# Correct message at buf[0x5d], 0x21 bytes  
correct_buf = bytearray(buf)  
key_20b0 = binary[0x20b0:0x20c0]  
key_20c0 = binary[0x20c0:0x20d0]  
for i in range(16):  
correct_buf[0x5d + i] ^= key_20b0[i]  
correct_buf[0x6d + i] ^= key_20c0[i]  
correct_buf[0x7d] ^= 0x58  
print(f"Correct msg: {bytes(correct_buf[0x5d:0x5d+0x21])}")  
```

### Exploit  
\- Exploit 代码未在本地标准 `solution/` 目录找到，可能嵌在外部 WP 文本中。  
\- 已在上方 WP 小节插入相关文本来源，可继续抽取为独立脚本。

\---
