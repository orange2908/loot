---
title: "semaphore - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "semaphore", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "im = Image.open(\"download.gif\")"
source:
  name: "CTFtime writeup #39899"
  url: "https://ctftime.org/writeup/39899"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "semaphore"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** semaphore
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39899>

---
```  
from PIL import Image  
im = Image.open("download.gif")

positions = [  
(7,28),  
(9,43),  
(27,45),  
(40,43),  
(44,28),  
(42,14),  
(33,4),  
(9,14),  
]

mapping = {  
255: 'Q',  
5: 'B',  
6: 'A',  
36: 'E',  
20: 'F',  
12: 'G',  
129: 'O',  
10: 'N',  
4: 'D',  
65: 'P',  
66: 'K',  
34: 'L',  
130: 'I',  
3: 'H',  
18: 'M',  
16: 'J',  
132: 'C',  
17: 'R',  
}

hexmap = {  
'A': '0',  
'B': '1',  
'C': '2',  
'D': '3',  
'E': '4',  
'F': '5',  
'G': '6',  
'H': '7',  
'I': '8',  
'J': '9',  
'K': 'A',  
'L': 'B',  
'M': 'C',  
'N': 'D',  
'O': 'E',  
'P': 'F',  
}

flag = ""

data = ""

im.seek(0)

# To iterate through the entire gif  
try:  
while 1:  
value = sum([0 if im.getpixel(p) == (255,255,255) else (1 << i) for (i,p) in enumerate(positions)])  
if value in mapping:  
flag += mapping[value] * (([im.info](http://im.info)['duration']) // 500)  
else:  
print(f"Unknown value {value} at {im.tell()}")  
  
if im.tell() > 4 and mapping[value] != "R":  
data += hexmap[mapping[value]] * (([im.info](http://im.info)['duration']) // 500)  
  
#im.save(f"{im.tell()}.png")  
im.seek(im.tell()+1)  
except EOFError:  
pass # end of sequence

print(flag)

print(data)

print(bytes.fromhex(data))  
```
