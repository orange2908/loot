---
title: "limit - smileyCTF 2025"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "fsop", "tcache-poisoning", "smileyctf", "smileyctf-2025", "2025", "ctf-writeup"]
summary: "Exploit the off-by-null bug to create overlapping chunks, then leverage tcache poisoning in an interesting way to bypass the heap limit restriction."
source:
  name: "CTFtime writeup #40331"
  url: "https://ctftime.org/writeup/40331"
original_source: "https://razvan.sh/posts/limit-smileyctf/"
ctf:
  name: "smileyCTF 2025"
  year: 2025
  challenge: "limit"
---

## Metadata

- **CTF:** smileyCTF 2025
- **Task:** limit
- **Author team:** OctalO
- **CTFtime tags:** pwn, heap, tcache
- **CTFtime:** <https://ctftime.org/writeup/40331>
- **Original writeup:** <https://razvan.sh/posts/limit-smileyctf/>

---
### Exploit summary

Exploit the off-by-null bug to create overlapping chunks, then leverage tcache poisoning in an interesting way to bypass the heap limit restriction. Instead of allocating chunks beyond the boundary, allocate a chunk inside the tcache entries array itself. Abuse this primitive to leak stack and binary addresses by redirecting allocations to arbitrary memory locations and reading the next chunk pointer, then finally overwrite a chunk pointer in the global chunks array to point to stdout and perform a file struct exploit to gain shell access.

Full writeup link:  
[<https://razvan.sh/posts/limit-smileyctf/>](<https://razvan.sh/posts/limit-smileyctf/>)
