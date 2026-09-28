---
title: "nips - BCACTF 6.0"
category: "rev"
subcategory: "packers"
type: "writeup"
tags: ["mips", "tea", "32-bit", "rev", "upx", "reverse", "packer", "packers", "bcactf", "bcactf-6-0", "ctf-writeup"]
summary: "nips was a reverse engineering challenge involving a UPX-packed, stripped 32-bit MIPS binary."
source:
  name: "CTFtime writeup #40372"
  url: "https://ctftime.org/writeup/40372"
original_source: "https://www.vipin.xyz/blog/nips-bca2025"
ctf:
  name: "BCACTF 6.0"
  challenge: "nips"
---

## Metadata

- **CTF:** BCACTF 6.0
- **Task:** nips
- **Author team:** 0xf1sh
- **CTFtime tags:** mips, tea, 32-bit, ctf, rev, upx, reverse
- **CTFtime:** <https://ctftime.org/writeup/40372>
- **Original writeup:** <https://www.vipin.xyz/blog/nips-bca2025>

---
nips was a reverse engineering challenge involving a UPX-packed, stripped 32-bit MIPS binary. After unpacking, analysis revealed that the program encrypted input using the Tiny Encryption Algorithm (TEA) with four hardcoded keys and compared the result against a stored ciphertext. By identifying the TEA constant, extracting the keys, and replicating the algorithm, the ciphertext could be decrypted to obtain the flag.

For the full walkthrough, check out the detailed blog post [here](https://www.vipin.xyz/blog/nips-bca2025)
