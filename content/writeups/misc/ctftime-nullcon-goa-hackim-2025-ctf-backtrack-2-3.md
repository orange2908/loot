---
title: "backtrack - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "backtrack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We can open up the binary in ida and find a function which seems to get some registry key values."
source:
  name: "CTFtime writeup #39915"
  url: "https://ctftime.org/writeup/39915"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#backtrack"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "backtrack"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** backtrack
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39915>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#backtrack>

---
We can open up the binary in ida and find a function which seems to get some registry key values. After that's done, it passes that info on to a suspicious looking function which seems to be running some sort of decryption. Porting that decryption function over to python and running it on the encrypted file gives us a jpg of the flag

```python=  
FILENAME = "data.bin"

with open(FILENAME, "rb") as f:  
data = f.read()

def r8(offset):  
return data[offset]

def r16(offset):  
return int.from_bytes(data[offset:offset+2], 'little')

c = 0  
cur_offset = 4  
decrypted = bytearray()

while cur_offset < len(data):  
if c == 0:  
val = r16(cur_offset)  
cur_offset += 2  
c = 16  
  
if (val & 1) != 0:  
v8 = (r8(cur_offset) & 0xf0) << 4  
v7 = (r8(cur_offset) & 0xf) + 1  
v9 = v8 + r8(cur_offset + 1)  
cur_offset += 2  
assert len(decrypted) > v9, f"{len(decrypted) = } {v9 = :#x} {decrypted = }"

pos = len(decrypted) - v9  
for i in range(v7):  
decrypted.append(decrypted[pos + i])  
else:  
decrypted.append(r8(cur_offset))  
cur_offset += 1  
  
val >>= 1  
c -= 1

with open("dec.bin", "wb") as f:  
f.write(bytes(decrypted))  
```
