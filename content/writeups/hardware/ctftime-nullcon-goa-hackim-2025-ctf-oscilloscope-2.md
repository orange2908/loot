---
title: "oscilloscope - Nullcon Goa HackIM 2025 CTF"
category: "hardware"
subcategory: "deserialization"
type: "writeup"
tags: ["hardware", "deserialization", "oscilloscope", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The given file consisted of three numpy arrays"
source:
  name: "CTFtime writeup #39956"
  url: "https://ctftime.org/writeup/39956"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "oscilloscope"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** oscilloscope
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39956>

---
## Rev / Oscilloscope

The given file consisted of three numpy arrays  
* timestamp   
* clock   
* signal 

The goal was to sample the signal on every rising edge of the clock signal into 0s and 1s. We can use `np.diff` to calculate derivative of the clock signal which will give us impulses on rising edge. We can use the index of those impulses to sample the message signal, apply thresholding and get the binary sequence. 

#### Solve script

```python  
import pickle  
import numpy as np  
import matplotlib.pyplot as plt

obj = pickle.load(open("./trace.pckl", "rb"))  
arr1 = np.array(obj[1])  
arr2 = np.array(obj[2])

#clamp valus  
arr1[arr1 > 3] = 3  
arr1[arr1 < 0] = 0

#clamp clock  
arr2[arr2 < 0.5] = 0

lval = 13000  
rval = 250000 + 13000

#derivative  
arr1_d = np.diff(arr1)  
arr1_d[arr1_d < 0] = 0

#sample index  
samples_idx = arr1_d > 1

#filtering to remove repetitive points  
filtered = [samples_idx[0]]  
idxs = []  
for i in range(len(arr1_d)):  
if arr1_d[i] > 1 :  
idxs.append(i)  
for i in range(1, len(idxs)):  
if idxs[i] - filtered[-1] > 50 :  
filtered.append(idxs[i])

#extracting samples in arr5  
arr5 = np.zeros(len(arr2)-1)  
mask = np.array([False] * (len(arr2)-1))  
mask[filtered] = True  
arr5[(arr2[:-1] > 1) & (mask)] = 3  
arr5[(arr2[:-1] < 1) & (mask)] = -1

#extracting points  
mask2 = np.abs(arr5[lval: rval ]) > 0.5  
points = arr5[lval : rval ][mask2]

#making bins of 9 bits  
points = points[:-1].reshape(-1, 9)   
points = (points > 0).astype("uint8")  
bts = []  
for i in points :  
bts.append("".join(list(map(str, i.tolist()))))

val = []  
for i in bts:  
val.append(int(i[:-1], 2)) #take bits from index 0-7

print(bytes(val))  
```
