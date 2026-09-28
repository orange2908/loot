---
title: "[INSERT CHALLENGE TITLE HERE] - CTF@CIT 2026"
category: "stego"
subcategory: "metadata"
type: "writeup"
tags: ["stego", "exiftool", "exif", "jpeg", "insert", "title", "here", "metadata", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Category: Steganography"
source:
  name: "CTFtime writeup #40750"
  url: "https://ctftime.org/writeup/40750"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "[INSERT CHALLENGE TITLE HERE]"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** [INSERT CHALLENGE TITLE HERE]
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40750>

---
# [INSERT CHALLENGE TITLE HERE] — Writeup

\- Category: Steganography  
\- Value: 672 pts (329 solves)  
\- Author: boom

## Challenge

A single `flag.jpg` showing the text "[INSERT A HIDDEN MESSAGE OR SOMETHING..]". Everything about this challenge is a placeholder joke — title, description, and rendered message are all template filler. The hidden message lives in the JPEG metadata.

## Solve

`file flag.jpg` already prints the flag — it's stored in the EXIF `ImageDescription` tag:

```text  
$ file files/flag.jpg  
flag.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16,  
Exif Standard: [TIFF image data, big-endian, direntries=5,  
description=CIT{ur_w4rm1ng_up_n0w}, ...], ...  
```

Equivalent probes:

```bash  
exiftool flag.jpg # ImageDescription: CIT{ur_w4rm1ng_up_n0w}  
xxd flag.jpg | grep -a 'CIT{'  
# 00000060: ... CIT{ur_w  
# 00000070: 4rm1ng_up_n0w}...  
```

The Exif APP1 segment starts at offset `0x14`; the TIFF `ImageDescription` (tag `0x010e`) sits at offset `0x26`, with its string stored starting at `0x68`.

## Flag

```text  
CIT{ur_w4rm1ng_up_n0w}  
```

## Files

\- [files/flag.jpg](files/flag.jpg) — the image with the flag in EXIF  
\- [scripts/[solve.sh](http://solve.sh)](scripts/[solve.sh](http://solve.sh)) — one-liner extractor  
\- [solution/flag.txt](solution/flag.txt) — recorded submission
