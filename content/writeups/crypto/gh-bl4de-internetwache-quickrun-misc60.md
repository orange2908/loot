---
title: "QuickRun Misc60 - internetwache 2016"
category: "crypto"
subcategory: "image"
type: "writeup"
tags: ["crypto", "qr-code", "base64", "quickrun", "misc60", "image"]
summary: "We get text file contains long Base64 strings (see README.txt)."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/internetwache_2016/QuickRun_Misc60_writeup.md"
ctf:
  name: "internetwache"
  year: 2016
  challenge: "QuickRun Misc60"
---

## Source

- **CTF:** internetwache 2016
- **Challenge:** QuickRun Misc60
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/internetwache_2016/QuickRun_Misc60_writeup.md>

---
# Quick Run (Misc, 60pts)

---

## Problem

Get the flag ! :)

## Solution

We get text file contains long Base64 strings (see README.txt).  Each string is one QR code (27 in total) and every QR code equals one sign in flag.

Using simple Python script I've ripped all QR codes into single file:

```python
#!/usr/bin/python
import base64

f = open("README.txt").read().split("\n")
qrcode = ""
tmp = ""
i = 1

fout = open("qrcodes.txt", "a+")

for p in f:
    tmp += p
    if len(p) < 77 and p.endswith(("ilogK","==","Ao=")):
        qrcode = base64.b64decode(tmp)
        print "[+] save {} QRcode to file".format(i)
        fout.write(qrcode + "\n\n\n")
        tmp = ""
        i += 1
        
fout.close()

print "[+] end"

```

Then I've just scanned them one by one directly from my laptop screen using my smartphone and simple QR code reader.

Finally I've get the flag:

```
IW{QR_C0DES_RUL3}
```
