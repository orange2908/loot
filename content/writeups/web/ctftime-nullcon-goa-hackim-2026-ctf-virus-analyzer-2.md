---
title: "virus analyzer - Nullcon Goa HackIM 2026 CTF"
category: "web"
type: "writeup"
tags: ["web", "virus", "analyzer", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "A \"secure\" virus analyzer service that scans uploaded ZIP files."
source:
  name: "CTFtime writeup #40580"
  url: "https://ctftime.org/writeup/40580"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "virus analyzer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** virus analyzer
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40580>

---
**Challenge Description**:  
A "secure" virus analyzer service that scans uploaded ZIP files. The author claimed "To make it more secure, I did not provide any source code."

**Analysis**:  
The service allows users to upload ZIP files, extracts them, and scans the contents.  
1\. **Exploration**: We tested various file extensions and payloads.  
\- Standard EICAR files were uploaded but "No Virus Detected" was returned, which was suspicious.  
\- Uploading a `.php` file resulted in it being deleted or blocked (404 Not Found), while other extensions like `.txt`, `.php3`, `.phtml` were extracted but not executed (served as text).  
2\. **Vulnerability**: The "virus scanner" likely implements a blacklist for `.php` files to prevent execution. However, the blacklist check appeared to be case-sensitive, while the underlying PHP server configuration (Apache/PHP-FPM) handles extensions case-insensitively on some systems or had a specific misconfiguration allowing `.PHP`.  
3\. **Hint**: A hint suggested that "PHP's built-in development server treats .PHP, .Php, .pHP (any case variation) as PHP files and executes them."

**Solution**:  
1\. **Bypass Filter**: We created a ZIP containing a PHP webshell named `shell.PHP` (mixed case).  
2\. **Upload & Execute**: The server's security filter (likely a simple `strpos($filename, '.php')` or similar case-sensitive check) failed to block `.PHP`, but the PHP server executed it.  
3\. **Retrieve Flag**: We accessed the uploaded `shell.PHP` and executed `cat /flag.txt`.

**Solver**: [[solve_case_bypass.py](http://solve_case_bypass.py)](file:///home/mritunjya/ctf/2026/nullcon/web/virus_analyzer/[solve_case_bypass.py](http://solve_case_bypass.py))

**Flag**: `ENO{R4C1NG_UPL04D5_4R3_FUN}`
