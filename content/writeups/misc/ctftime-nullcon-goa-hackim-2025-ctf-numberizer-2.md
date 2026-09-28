---
title: "numberizer - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "numberizer", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Since there's a 4 letters limit for each number"
source:
  name: "CTFtime writeup #39939"
  url: "https://ctftime.org/writeup/39939"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "numberizer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** numberizer
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39939>

---
Since there's a 4 letters limit for each number

![image](<https://hackmd.io/_uploads/HJnHDGzFke.png>)

Enter 1e19 so that it gets overflow to `9223372036854775807 (2 ^ 63 - 1)`

Add 1 and it becomes `2 ^ 63` thus flipping the sign bit and we get a negative number `-9223372036854775808`

Submit `[1e19, 1]` and win a flag:

![image](<https://hackmd.io/_uploads/SJUSOzftkx.png>)

Flag: `ENO{INTVAL_IS_NOT_ALW4S_P0S1TiV3!}`
