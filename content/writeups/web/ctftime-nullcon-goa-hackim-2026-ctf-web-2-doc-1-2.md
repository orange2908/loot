---
title: "Web 2 Doc 1 - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["ssrf", "flask", "base64", "web", "doc", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Another variant of the Web2Doc PDF converter."
source:
  name: "CTFtime writeup #40576"
  url: "https://ctftime.org/writeup/40576"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Web 2 Doc 1"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Web 2 Doc 1
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40576>

---
**Challenge Description**:  
Another variant of the Web2Doc PDF converter. This version hides the flag behind an internal endpoint that implements a character-by-character guessing oracle.

**Analysis**:  
1\. **Probing Internal Services**: The external converter runs on port 5002, but we discovered Flask's development server on port 5000 by testing `http://0.0.0.0:5000/`. The `0.0.0.0` address slips through the private IP blacklist because Python's `ipaddress` library doesn't classify it as private, yet Linux routes it to localhost.  
2\. **The Hidden Oracle**: An endpoint at `/admin/flag` accepts query parameters `i` (index) and `c` (character). It responds with HTTP 200 if the character matches the flag at that position, or 404 otherwise. Direct SSRF requests fail due to an `X-Fetcher: internal` header check.  
3\. **Exploiting WeasyPrint's Resource Loading**: When WeasyPrint renders HTML to PDF, it fetches external resources (like `` sources) independently—without the blocking header. The key insight: WeasyPrint only displays an image's `alt` text when the image fails to load. A 200 response (correct guess) hides the alt text; a 404 (wrong guess) renders it.

**Solution**:  
We crafted HTML payloads with embedded images pointing to the oracle:  
```html  
![](http://0.0.0.0:5000/admin/flag?i=4&c=w)  
```  
Using `[httpbin.org/base64/](http://httpbin.org/base64/)` to host our payloads (avoiding the need for an external server), we submitted each URL to the converter. By parsing the resulting PDF text, we determined:  
\- Alt text **absent** → character is correct (200 OK)  
\- Alt text **present** → character is wrong (404)

Iterating through each flag position with all printable characters extracted the complete flag.

**Solver**: [[solve_oracle_httpbin.py](http://solve_oracle_httpbin.py)](file:///home/mritunjya/ctf/2026/nullcon/web/web_2_doc_1/[solve_oracle_httpbin.py](http://solve_oracle_httpbin.py))

**Flag**: `ENO{weasy_pr1nt_can_h4v3_bl1nd_ssrf_OK!}`
