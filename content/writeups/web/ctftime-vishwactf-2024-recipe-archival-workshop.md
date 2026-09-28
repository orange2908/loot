---
title: "RECIPE ARCHIVAL WORKSHOP - VishwaCTF 2024"
category: "web"
subcategory: "file-upload"
type: "writeup"
tags: ["web", "web-exploitation", "file-upload", "recipe", "archival", "workshop", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "The given website has a file upload form."
source:
  name: "CTFtime writeup #39506"
  url: "https://ctftime.org/writeup/39506"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/Recipe%20Archival%20Workshop.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "RECIPE ARCHIVAL WORKSHOP"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** RECIPE ARCHIVAL WORKSHOP
- **Author team:** CyberCellVIIT
- **CTFtime tags:** web_exploitation
- **CTFtime:** <https://ctftime.org/writeup/39506>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/Recipe%20Archival%20Workshop.pdf>

---
Solution:  
The given website has a file upload form. The challenge title mentions archives. If we search on Google, we find that common file extensions for archives include TIFF, RAW, etc.

The abbreviation of the challenge title might lead solvers to think of the RAW file extension, but that is a false lead. Instead, solvers must upload a TIFF file (under 5 MB in size) to trigger an alert containing the flag.

```  
Flag:

VishwaCTF{today_i_wanted_to_eat_a_croissant_QUASO}  
```
