---
title: "abroad study notes - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "abroad", "study", "notes", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We are given a corrupted jpeg image which looks like its data streams are scratched."
source:
  name: "CTFtime writeup #39985"
  url: "https://ctftime.org/writeup/39985"
original_source: "https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "abroad study notes"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** abroad study notes
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39985>
- **Original writeup:** <https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/>

---
# abroad_study_notes

## Description

We are given a corrupted jpeg image which looks like its data streams are scratched.

## Solution

\- Now from the JPEG documentation we find,  
\- “If a 0xff byte occurs in the compressed image data either a zero byte (0x00) or a marker identifier follows it. Normally the only marker that should be found once the image data is started is an EOI. When a 0xff byte is found followed by a zero byte (0x00) the zero byte must be discarded.”  
\- So on inspecting the given jpeg we find it has `ff 07`  
\- markers causing the distortion so we just fix them to `ff 00`  
\- and our jpeg restores to original one.

\- Documentation to refer : [jpeg-format-layout](<http://mcatutorials.com/mca-tutorials-jpeg-file-layout-format-2-c-practical.php>)

## Flag  
`ENO{o7_t0_4ll_r3pl4c3d_07}`
