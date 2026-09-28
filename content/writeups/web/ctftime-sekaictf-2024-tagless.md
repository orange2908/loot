---
title: "Tagless - SekaiCTF 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "csp-bypass", "xss", "cors", "content-spoofing", "content-injection", "mime-sniffing", "mime", "sekaictf", "sekaictf-2024", "2024", "ctf-writeup"]
summary: "Despite a sound Content Security Policy (CSP) in place, the application was"
source:
  name: "CTFtime writeup #39476"
  url: "https://ctftime.org/writeup/39476"
original_source: "https://www.justus.pw/writeups/sekai-ctf/tagless.html"
ctf:
  name: "SekaiCTF 2024"
  year: 2024
  challenge: "Tagless"
---

## Metadata

- **CTF:** SekaiCTF 2024
- **Task:** Tagless
- **Author team:** seasonal allergies
- **CTFtime tags:** csp-bypass, xss, cors, content-spoofing, content-injection, mime-sniffing, mime
- **CTFtime:** <https://ctftime.org/writeup/39476>
- **Original writeup:** <https://www.justus.pw/writeups/sekai-ctf/tagless.html>

---
Despite a sound Content Security Policy (CSP) in place, the application was  
susceptible to four vulnerabilities:

\- The HTTP error handler allows arbitrary content injection  
\- HTTP responses do not instruct the browser to stop sniffing MIME types  
\- Untrusted user input is not sanitized correctly, due to a faulty  
blacklist-based sanitization function  
\- A harmless-looking input form allows chaining the above vulnerabilities to a  
complete exploit

Refer to my original writeup here: <https://www.justus.pw/writeups/sekai-ctf/tagless.html>
