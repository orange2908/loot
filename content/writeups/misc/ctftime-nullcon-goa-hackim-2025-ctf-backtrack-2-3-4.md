---
title: "backtrack - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "backtrack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "In sample file, sub401690 is decompress function."
source:
  name: "CTFtime writeup #39895"
  url: "https://ctftime.org/writeup/39895"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "backtrack"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** backtrack
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39895>

---
In sample file, sub_401690 is decompress function. Here is script solve:

```  
def decompress(data):  
if len(data) < 4:  
raise ValueError("Invalid data")  
if data[0] == 1:  
return data[4:]  
out = bytearray()  
i = 4  
n = len(data)  
while i < n:  
if i + 1 >= n:  
break  
flag = data[i] | (data[i + 1] << 8)  
i += 2  
bits = 16  
while bits > 0 and i < n:  
if flag & 1:  
if i + 1 >= n:  
raise ValueError("Incomplete back-reference")  
first = data[i]  
length = (first & 0x0F) + 1  
offset = ((first >> 4) << 8) | data[i + 1]  
i += 2  
if offset > len(out):  
raise ValueError("Invalid offset")  
src_index = len(out) - offset  
for _ in range(length):  
out.append(out[src_index])  
src_index += 1  
else:  
out.append(data[i])  
i += 1  
flag >>= 1  
bits -= 1  
return bytes(out)

with open('data.bin', "rb") as f:  
data = f.read()  
decompressed = decompress(data)  
with open('output', "wb") as f:  
f.write(decompressed)  
```
