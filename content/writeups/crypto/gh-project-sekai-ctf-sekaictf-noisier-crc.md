---
title: "noisier crc - sekaictf 2023"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "noisier", "crc", "cryptography", "noisier-crc", "sekaictf"]
summary: "In the writeup of the previous challenge, we claim that the secret has the form"
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/crypto/noisier-crc/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "noisier crc"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** noisier crc
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/crypto/noisier-crc/solution/README.md>

---
## Solution

In the writeup of the previous challenge, we claim that the secret has the form

$$\sum_{i} c_{i, j_i}A_i$$

If we use the same idea, all $A_i$ has degree $16n$, and we have $13n$ basis. Give that $n \le 133$ we won't be able to recover the 512-bit secret. The trick is to modify the equation to

$$\text{secret} + \sum_{i} c_{i, 0}A_i = \sum_{i} (c_{i, j_i} - c_{i, 0})A_i$$

Now the left hand side is spanned by $12n$ basis instead of $13n$, and we can recover unique secret up to $4 \times 133 = 532$ bits.
