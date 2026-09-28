---
title: "Free Delivery - UMassCTF 2024"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["engineering", "rev", "xor", "jadx", "ghidra", "android", "base64", "static-analysis", "umassctf", "umassctf-2024", "2024", "ctf-writeup"]
summary: "A detailled writeup can be found here."
source:
  name: "CTFtime writeup #39128"
  url: "https://ctftime.org/writeup/39128"
original_source: "https://ihuomtia.onrender.com/umass-rev-free-delivery"
ctf:
  name: "UMassCTF 2024"
  year: 2024
  challenge: "Free Delivery"
---

## Metadata

- **CTF:** UMassCTF 2024
- **Task:** Free Delivery
- **Author team:** PH4NT0MS
- **CTFtime tags:** engineering, rev, xor, jadx, ghidra, android
- **CTFtime:** <https://ctftime.org/writeup/39128>
- **Original writeup:** <https://ihuomtia.onrender.com/umass-rev-free-delivery>

---
# Full writeup  
A detailled writeup can be found [here](<https://ihuomtia.onrender.com/umass-rev-free-delivery>).

# Summarized Solution  
\- Decompile the apk using `jadx`  
\- Extract a base64 encoded string from `MainActivity.java`, the string is `AzE9Omd0eG8XHhEcHTx1Nz0dN2MjfzF2MDYdICE6fyMa`.  
\- Decode the string and then xor it with the key `SPONGEBOBSPONGEBOBSPONGEBOBSPONGEBOBSPONGEBOB`, then you'll obtain `Part 1: UMASS{0ur_d3l1v3ry_squ1d_`  
\- In the decompiled apk, look for a shared library named `[libfreedelivery.so](http://libfreedelivery.so)`, decompile it and extract some data that was xored with the byte `0x55`, the xored bytes are `\x30\x36\x3d\x3a\x75\x77\x05\x34\x27\x21\x75\x01\x22\x3a\x6f\x75\x22\x64\x39\x39\x0a\x37\x27\x64\x3b\x32\x0a\x64\x21\x0a\x27\x64\x32\x3d\x21\x0a\x65\x23\x66\x27\x0a\x74\x28\x77\x55`, xor them with `0x55` and you'll obtain `echo "Part Two: w1ll_br1ng_1t_r1ght_0v3r_!}"\x00'`  
\- Put together with the first part, we get the full flag: `UMASS{0ur_d3l1v3ry_squ1d_w1ll_br1ng_1t_r1ght_0v3r_!}`
