---
title: "Minesweeper 2 - BITSCTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "minesweeper", "bitsctf", "bitsctf-2025", "2025", "ctf-writeup"]
summary: "A \\\\\\\\(m\\times n\\\\\\\\) board yields a system of linear equations in \\\\\\\\(mn\\\\\\\\) variables."
source:
  name: "CTFtime writeup #40043"
  url: "https://ctftime.org/writeup/40043"
original_source: "https://gopherhack.com/posts/bitsctf2025-minesweeper-2/"
ctf:
  name: "BITSCTF 2025"
  year: 2025
  challenge: "Minesweeper 2"
---

## Metadata

- **CTF:** BITSCTF 2025
- **Task:** Minesweeper 2
- **Author team:** GopherHack
- **CTFtime:** <https://ctftime.org/writeup/40043>
- **Original writeup:** <https://gopherhack.com/posts/bitsctf2025-minesweeper-2/>

---
A \\\\(m\times n\\\\) board yields a system of linear equations in \\\\(mn\\\\) variables. Each variable \\\\(a_\\{ij\\}\\\\) represents the number of mines at row \\\\(i\\\\), column \\\\(j\\\\). Each equation sets a constraint on how many mines can be at a location's neighbors based on the number in its tile. For example, if there are \\\\(b_\\{23\\}\\\\) mines adjacent to a non-edge tile at row \\\\(2\\\\), column \\\\(3\\\\), the correpsonding equation is  
\\\\[a_\\{13\\} + a_\\{22\\} + a_\\{33\\} + a_\\{24\\} = b_\\{23\\}.\\\\]

Normally, such systems are solved using Gaussian elimination in \\\\(O((mn)^3)\\\\). Luckily, our system of equations is very sparse, so `scipy.sparse` can solve the system more quickly.

Flag: `BITSCTF{D0_u_y34rn_f0R_th3_m1n3s?}`

The final solve script can be found [here](<https://gopherhack.com/_astro/solve.pfXOrQYr.py>).
