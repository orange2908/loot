---
title: "Happy Valentine’s Day - VishwaCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "happy", "valentine", "day", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "We are given this source code:"
source:
  name: "CTFtime writeup #39531"
  url: "https://ctftime.org/writeup/39531"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/Happy%20Valentines%20Day.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "Happy Valentine’s Day"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** Happy Valentine’s Day
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39531>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/Happy%20Valentines%20Day.pdf>

---
Solution:  
We are given this source code:

```  
from PIL import Image   
from itertools import cycle 

def xor(a, b):   
return [i^j for i, j in zip(a, cycle(b))] 

f = open("original.png", "rb").read()   
key = [f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]]   
enc = bytearray(xor(f, key))   
open('enc.txt', 'wb').write(enc)  
```  
Here we can see that the encryption algorithm used is XORing the original byte array of the image with the first 8 bytes of the image. Since the original image is in PNG format, the first 8 bytes are fixed: 137 80 78 71 13 10 26 10.

By using the property of XOR (A ^ B = C and C ^ B = A), we can decrypt the image by XORing it with these fixed bytes.

Decryption Script:  
```

from PIL import Image   
from itertools import cycle 

def xor(a, b):   
return [i^j for i, j in zip(a, cycle(b))] 

f = open("enc.txt", "rb").read()   
key = [137, 80, 78, 71, 13, 10, 26, 10] 

enc = bytearray(xor(f, key))   
open('original.png', 'wb').write(enc)   
Image.open('original.png').show()  
```  
```  
Flag:  
VishwaCTF{h3ad3r5_f0r_w1nn3r5}  
```
