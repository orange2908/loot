---
title: "Web 2 Doc 2 - Nullcon Goa HackIM 2026 CTF"
category: "web"
type: "writeup"
tags: ["web", "doc", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Same Web2Doc PDF converter, but /admin/flag is removed."
source:
  name: "CTFtime writeup #40577"
  url: "https://ctftime.org/writeup/40577"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Web 2 Doc 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Web 2 Doc 2
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40577>

---
**Challenge Description**:  
Same Web2Doc PDF converter, but `/admin/flag` is removed. We need `/flag.txt`.

**Analysis**:  
The converter uses WeasyPrint to render a URL to PDF. WeasyPrint supports **PDF attachments** via:  
```html  
<link rel="attachment" href="...">  
```  
If the URL is a `file://` path, WeasyPrint will embed that file in the resulting PDF. Web2Doc v2 allows `file://` in attachments (even though direct `file://` fetches are blocked).

**Solution**:  
1\. Host a small HTML page (I used `[paste.rs](http://paste.rs)`) with:  
```html  
<link rel="attachment" href="file:///flag.txt">  
```  
2\. Fetch the captcha from the landing page (`<div class="captcha-display">...`).  
3\. POST to `/convert` with `url=<[paste.rs](http://paste.rs) link>` and `captcha_answer=<captcha>`.  
4\. Extract the embedded file from the PDF using `pdfdetach`.

**Solver**:  
`web/web_2_doc_2/[solve.py](http://solve.py)`

**Flag**:  
`ENO{weasy_pr1nt_can_h4v3_f1l3s_1n_PDF_att4chments!}`
