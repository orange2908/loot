---
title: "emoji - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "emoji", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40658"
  url: "https://ctftime.org/writeup/40658"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/emoji/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "emoji"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** emoji
- **Author team:** RootRunners
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40658>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/emoji/README.md>

---
# emoji

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Misc   
**Points:** 50 

## Overview  
The challenge hides a message in Unicode Variation Selectors appended to a visible emoji. These selectors are usually invisible, making them useful for steganography.

## Encoding Scheme  
The hidden bytes are encoded using the Variation Selectors Supplement range:  
\- Range: `U+E0100` to `U+E01EF`  
\- For each selector:

```  
byte = (codepoint - 0xE0100) + 16  
```

That produces a byte stream that can be decoded as ASCII/UTF-8.

## Decoder (Python)  
Paste the full emoji string into `s`.

```python  
def decode_vs(s: str) -> bytes:  
out = bytearray()  
for ch in s:  
cp = ord(ch)  
if 0xE0100 <= cp <= 0xE01EF:  
out.append((cp - 0xE0100) + 16)  
return bytes(out)

# s = "<paste the full string here>"  
data = decode_vs(s)

print("RAW BYTES:", data)  
try:  
print("ASCII/UTF-8:", data.decode("utf-8"))  
except UnicodeDecodeError:  
print("Not UTF-8. HEX:", data.hex())  
```

## Flag  
```  
ENO{EM0J1S_UN1COD3_1S_MAG1C}  
```
