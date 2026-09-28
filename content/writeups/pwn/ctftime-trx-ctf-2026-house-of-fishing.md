---
title: "house-of-fishing - TRX CTF 2026"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "largebin", "house-of-fishing", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "Leakless glibc-2.39 exploit on a heap-style chal whose only primitives are create/update/delete/copy (with no offset, no overflow, no read)."
source:
  name: "CTFtime writeup #40715"
  url: "https://ctftime.org/writeup/40715"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-house-of-fishing-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "house-of-fishing"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** house-of-fishing
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40715>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-house-of-fishing-writeup>

---
TL;DR  
Leakless glibc-2.39 exploit on a heap-style chal whose only primitives are create/update/delete/copy (with no offset, no overflow, no read). The win condition is *admin == 0xdeadbeefdeadcafe where admin points to a fixed mmap'd page at 0x1337000. Solution chains a largebin attack to plant a heap pointer at *(0x1337008), then a tcache stash unlink through a fake chunk header at 0x1336FF0 so that tcache_put writes entries[bin] = 0x1337000 directly. The next malloc(0x90) returns the admin page; we write the magic value and trigger the hidden case 5 to call system("/bin/sh").
