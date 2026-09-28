---
title: "Car Crash - CTF@CIT 2026"
category: "stego"
subcategory: "image"
type: "writeup"
tags: ["stego", "xor", "lsb", "zsteg", "exiftool", "base64", "image", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Category: Steganography"
source:
  name: "CTFtime writeup #40751"
  url: "https://ctftime.org/writeup/40751"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Car Crash"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Car Crash
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40751>

---
# Car Crash — Writeup

\- **Category:** Steganography  
\- **Points:** 980  
\- **Flag:** `CIT{7E3qU4wE}`

## Observations

\- `exiftool` on [car_crash.png](files/car_crash.png) reports six `tEXt` chunks with  
plausible-but-nonsense keys — `render-group-bsDFp`, `palette-trace-A8sBeb`,  
`map-stamp`, `digest_path`, `manifestLayer-9aG4A`, `palette_refs-BB6oT7C6` —  
each carrying a base64-looking blob. These turn out to be **decoys**  
(one blob has length 97, which is not a valid base64 length — a hint they  
are not meant to be decoded).  
\- The alpha channel has **only two distinct values** (254 and 255): a strong  
steganography signal that its bit-0 (LSB) plane carries data.  
\- Viewing any single-channel LSB plane as a 1-bit image shows noisy text-like  
patterns but nothing readable. Likewise for concatenations and for per-chunk  
decodings.  
\- The trick: the RGBA LSB planes *each* carry rendered text plus a common  
carrier noise. **XOR-ing two planes cancels the carrier and reveals one  
clean text layer.**

## Solution

Render the bit-0 plane of `G XOR A` as a black-and-white image:

```python  
from PIL import Image  
img = Image.open("car_crash.png")  
w, h = img.size  
px = list(img.getdata())  
out = Image.new("L", (w, h))  
out.putdata([((p[1] ^ p[3]) & 1) * 255 for p in px])  
out.save("ga_xor.png")  
```

Inside the rendered noise, a centered base64 string is clearly visible:

```text  
Q0lUezdFM3FVNHdFfQ==  
```

Decoding it gives the flag:

```python  
>>> base64.b64decode("Q0lUezdFM3FVNHdFfQ==")  
b'CIT{7E3qU4wE}'  
```

## Why G⊕A specifically

The author drew a single text layer into two channel LSB planes, XOR-ed with  
a shared noise pattern. XOR-ing those two planes back together cancels the  
noise and leaves the text. Any other channel pair still carries a different,  
uncancelled noise — that's why only the G⊕A view is legible.

## Reproduce

```sh  
python3 scripts/[solve.py](http://solve.py)  
# writes files/extractions/ga_xor.png and prints the flag  
```

## Red herrings

\- The six `tEXt` chunks of base64-looking blobs.  
\- `zsteg`'s wbStego hit on `b1,bgr,lsb,xy` — a false positive from the  
3-bit periodicity of a per-pixel RGB LSB stream.
