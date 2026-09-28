---
title: "Xor Gif (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "xor", "gif", "forensics"]
summary: "Personal note: Xor Gif (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/XOR GIF.md"
---

#xor #gifs #gif

```python
# xortool to fint the key then run this solver

def xor_bytes(data, key):
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

enc = 'fun.gif'
dec = 'decrypted.gif'
key = b'\xf0\x07\xba\x11'

with open(enc, 'rb') as file:
    enc_data = file.read()

res = xor_bytes(enc_data, key)

with open(dec, 'wb') as file:
    file.write(res)
```

---

*From your own notes: `Forensics/XOR GIF.md`*
