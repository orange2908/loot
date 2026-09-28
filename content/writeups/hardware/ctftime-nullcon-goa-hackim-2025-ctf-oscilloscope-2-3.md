---
title: "oscilloscope - Nullcon Goa HackIM 2025 CTF"
category: "hardware"
subcategory: "deserialization"
type: "writeup"
tags: ["hardware", "deserialization", "oscilloscope", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "data[0] represents time, data[1] represents the clock, and data[2] represents the observed signals."
source:
  name: "CTFtime writeup #39914"
  url: "https://ctftime.org/writeup/39914"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#oscilloscope"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "oscilloscope"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** oscilloscope
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39914>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#oscilloscope>

---
`data[0]` represents time, `data[1]` represents the clock, and `data[2]` represents the observed signals. For each clock cycle, if the majority of `data[2]` values are greater than 1, observe it as 1; otherwise, observe it as 0. Split the result into 9-bit segments and interpret them as ASCII to obtain the flag.

```python=  
import pickle  
import matplotlib.pyplot as plt

def bitstring_to_bytes(s):  
return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

data = pickle.load(open("trace.pckl", "rb"))

FROM = 68000  
TO = 240000  
SAMPLES = 20

while data[1][FROM] > 1:  
FROM +=1  
while data[1][TO] > 1:  
TO -=1

idx = FROM + SAMPLES  
prev = idx  
result = ""  
while idx < TO:  
while sum(data[1][idx-SAMPLES:idx]) > SAMPLES:  
idx += 1  
t1 = idx  
while sum(data[1][idx-SAMPLES:idx]) < SAMPLES:  
idx += 1  
t2 = idx  
next = (t1+t2)//2  
if sum(data[2][prev:next])//(next-prev) > 1:  
result += "1"  
else:  
result += "0"  
prev = next  
data1 = data[1][FROM:TO]  
data2 = data[2][FROM:TO]  
x_values = data[0][FROM:TO]

result = result[1:]  
print(result)

b = b""  
for i in range(0,len(result), 9):  
b += int(result[i:i+8],2).to_bytes()  
print(b)  
# open("x", "wb").write(b)  
# plt.plot(x_values, data1, linestyle='-', color='b')  
# plt.plot(x_values, data2, linestyle='-', color='r')

# plt.xlabel('Index')  
# plt.ylabel('Value')

# plt.grid(True)

# plt.show()  
```
