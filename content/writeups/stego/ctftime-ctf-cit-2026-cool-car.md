---
title: "Cool Car - CTF@CIT 2026"
category: "stego"
subcategory: "image"
type: "writeup"
tags: ["stego", "lsb", "exiftool", "base64", "cool", "car", "image", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Category: Steganography"
source:
  name: "CTFtime writeup #40752"
  url: "https://ctftime.org/writeup/40752"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Cool Car"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Cool Car
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40752>

---
# Cool Car — Writeup

\- Category: Steganography  
\- Value: 979 pts  
\- Author: by **ronnie**

## Challenge

I got this cool car here, maybe you can find a flag.

Flag Format: `CIT{example_flag}`

## Recon

`cool_car.png` is an RGBA PNG. `exiftool`/`strings` shows lots of `x-random-*`  
`tEXt` chunks — those are a rabbit hole. The real payload is in the pixels.

Bit-plane sweep across the four channels: the red-channel LSB renders a giant  
`CYBERCIT{l00k_at_d3m_curv3s}` in ASCII-art form. This is **also a decoy**  
(wrong format, doesn't validate). The actual flag lives in the **alpha channel,  
LSB (plane 0)**.

## Solve

Extract the alpha LSB plane as a 1-bit image. A short base64 string is printed  
dead-centre of the plane; everything else is noise:

```text  
Q0lUezRWdTF1MXpofQ==  
```

Base64-decode it:

```python  
import base64  
base64.b64decode("Q0lUezRWdTF1MXpofQ==").decode()  
# 'CIT{4Vu1u1zh}'  
```

## Why the LLM got stuck

Red-LSB rendered a huge, plausible-looking `CYBERCIT{...}` banner, so the  
obvious move was to trust it and reshape it into `CIT{...}`. The correct plane  
(alpha-0) only shows a tiny base64 blob in the centre — easy to miss if you  
stop at the first bit-plane that "looks like" a flag. Lesson: sweep **every**  
channel's LSB, including alpha, and don't stop at the first readable artefact.

## Flag

```text  
CIT{4Vu1u1zh}  
```

## Files

\- [files/cool_car.png](files/cool_car.png) — stego image  
\- [scripts/[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py)) — extracts alpha-0 plane + decodes base64  
\- [solution/alpha_plane_0.png](solution/alpha_plane_0.png) — extracted plane (base64 visible at centre)  
\- [solution/flag.txt](solution/flag.txt) — recovered flag
