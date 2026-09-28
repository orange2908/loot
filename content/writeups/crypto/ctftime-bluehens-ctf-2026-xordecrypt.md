---
title: "XORDECRYPT - BlueHens CTF 2026"
category: "crypto"
type: "writeup"
tags: ["crypto", "cbc", "xor", "xordecrypt", "bluehens-ctf", "bluehens-ctf-2026", "2026", "ctf-writeup"]
summary: "\\- Hint: \"I feel CHAINED to my desk, looking for some positive FEEDBACK\""
source:
  name: "CTFtime writeup #40697"
  url: "https://ctftime.org/writeup/40697"
original_source: "https://github.com/pnimtsovych/WriteUp/tree/main/XORDECRYPT%20(BlueHens%20CTF%202026)"
ctf:
  name: "BlueHens CTF 2026"
  year: 2026
  challenge: "XORDECRYPT"
---

## Metadata

- **CTF:** BlueHens CTF 2026
- **Task:** XORDECRYPT
- **Author team:** LeetSh4d0ws
- **CTFtime:** <https://ctftime.org/writeup/40697>
- **Original writeup:** <https://github.com/pnimtsovych/WriteUp/tree/main/XORDECRYPT%20(BlueHens%20CTF%202026)>

---
# 0x67.png — XOR Decrypt Challenge Writeup

## Challenge Description

\- **File:** `0x67.png`  
\- **Hint:** *"I feel CHAINED to my desk, looking for some positive FEEDBACK"*  
\- **Flag format:** `UDCTF{}`

## Analysis

Two keywords in the hint stand out:  
\- **CHAINED** → chained XOR (each byte depends on the previous one)  
\- **FEEDBACK** → cipher feedback mode (CBC-style)

The key `0x67` is hidden in the filename itself.

A simple per-pixel XOR with `0x67` produces no result — the image stays noisy. The hint tells us we need **CBC-style chaining**, applied **separately per RGB channel**:

```  
decrypted[0] = cipher[0] XOR 0x67  
decrypted[i] = cipher[i] XOR cipher[i-1]  
```

## Solution

```python  
from PIL import Image  
import numpy as np  
from scipy.ndimage import gaussian_filter

# Load encrypted image  
img = Image.open('0x67.png')  
arr = np.array(img).astype(np.uint8)  
H, W, C = arr.shape  
key = 0x67

# CBC-style XOR decryption per channel  
result = np.empty_like(arr)  
for c in range(C):  
channel = arr[:, :, c].flatten()  
decrypted = np.empty_like(channel)  
decrypted[0] = channel[0] ^ key  
for i in range(1, len(channel)):  
decrypted[i] = channel[i] ^ channel[i-1]  
result[:, :, c] = decrypted.reshape(H, W)

Image.fromarray(result).save('decrypted.png')

# Reduce noise and crop flag text area  
gray = np.array(Image.fromarray(result).convert('L')).astype(float)  
smoothed = gaussian_filter(gray, sigma=1.5)  
crop = smoothed[480:515, 130:900]  
mn, mx = crop.min(), crop.max()  
stretched = ((crop - mn) / (mx - mn) * 255).astype(np.uint8)  
Image.fromarray(stretched).resize(  
(stretched.shape[1]*8, stretched.shape[0]*8), Image.LANCZOS  
).save('flag_text.png')  
```

The decrypted image reveals a landscape photo with the flag embedded as text in the middle:

![preview](<https://github.com/user-attachments/assets/74a214a8-95fa-4efb-80f1-32d23a2b36b6>)

## Flag

```  
UDCTF{x0r_T0_Th3_Fla@g}  
```
