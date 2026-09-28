---
title: "FacingWorlds - Hackers-Playground 2022"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "facingworlds", "miscellaneous", "hackers-playground", "perfectblue", "ctf-writeups"]
summary: "Check the balance of left/right."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/Hackers-Playground-2022/FacingWorlds/README.md"
ctf:
  name: "Hackers-Playground"
  year: 2022
  challenge: "FacingWorlds"
---

## Source

- **CTF:** Hackers-Playground 2022
- **Challenge:** FacingWorlds
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/Hackers-Playground-2022/FacingWorlds/README.md>

---
# Facing Worlds

Check the balance of left/right. If it's unbalance, it means 1.
If not, it means 0.

Here's the result from `stereo_decode.py`:
```
Score                 Type                                Text
------------------------------------------------------------------------------
153.71666666666664    le-parity-inv-ascii7                b'SCTF{Unr3aL_2_g0_b@ck_iN_Tim3}'
201.35000000000002    be-parity-inv-shift3-ascii7         b'|,"&-j\'dlHc/$O.`O$`,mo)g/")klK'
273.5                 le-start-inv-shift7-ascii7          b'j\x08e4Unr3aL_2_g0_b@ck_iN_Tim3}'
328.93548387096774    le-parity-shift7-ascii7             b'\x00V^U\\BUHFfOYPfPLgPN_NJPKXPUKIfA'
481.3                 le-inv-ascii8                       b'SCTF{Unr3aL_2_g0_b@ck_iN_Tim3}'
```
