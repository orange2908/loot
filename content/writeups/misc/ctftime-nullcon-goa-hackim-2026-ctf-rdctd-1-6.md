---
title: "rdctd 1-6 - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "pdf", "forensics", "rdctd", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "All rdctd tasks reference the same PDF and ask for different hidden flags."
source:
  name: "CTFtime writeup #40573"
  url: "https://ctftime.org/writeup/40573"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "rdctd 1-6"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** rdctd 1-6
- **Author team:** 正规子群.AI
- **CTFtime tags:** misc, pdf, forensics
- **CTFtime:** <https://ctftime.org/writeup/40573>

---
## rdctd 1-6 Combined Writeup

All `rdctd` tasks reference the same PDF and ask for different hidden flags.

### Unified Method

1\. Parse visible text and metadata (`pdfinfo`, `pdftotext`, `strings`).  
2\. Iterate through compressed `stream ... endstream` objects.  
3\. Attempt zlib inflate (normal and raw deflate).  
4\. Extract `ENO{...}` candidates and select by challenge index digit.

### Unified extractor

```python  
#!/usr/bin/env python3  
import re, zlib  
from pathlib import Path

FLAG_RE = re.compile(rb"ENO\\{[^\r\n\\}]{1,200}\\}")

def extract(pdf_bytes: bytes):  
out = set(m.group().decode('latin1','ignore') for m in FLAG_RE.finditer(pdf_bytes))  
for m in re.finditer(rb"stream\r?\n", pdf_bytes):  
s = m.end(); e = pdf_bytes.find(b"endstream", s)  
if e < 0: continue  
chunk = pdf_bytes[s:e]  
if chunk.endswith(b"\r\n"): chunk = chunk[:-2]  
elif chunk.endswith(b"\n"): chunk = chunk[:-1]  
for wb in (zlib.MAX_WBITS, -15):  
try:  
dec = zlib.decompress(chunk, wb)  
except Exception:  
continue  
out.update(x.group().decode('latin1','ignore') for x in FLAG_RE.finditer(dec))  
break  
return sorted(out)

pdf = Path('Planned-Flags-signed-2.pdf').read_bytes()  
for f in extract(pdf):  
print(f)  
```

### Notes

\- `rdctd 5` has a verified local solver in `misc/rdctd5/solution/[solution.py](http://solution.py)`.  
\- For the other rdctd variants, choose the candidate containing the requested digit (`1`..`6`).

## Exploit

See included steps and code blocks above.
