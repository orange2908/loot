---
title: "Calculator - CTF@CIT 2025"
category: "misc"
type: "writeup"
tags: ["misc", "whitespace", "calculator", "ctf-cit", "ctf-cit-2025", "2025", "ctf-writeup"]
summary: "The attached file has a .lua extension, indicating a Lua program."
source:
  name: "CTFtime writeup #40210"
  url: "https://ctftime.org/writeup/40210"
original_source: "https://github.com/isip-hs-whoami/CTF-writeup/blob/main/CTF%40CIT%202025/Calculator/writeup.md"
ctf:
  name: "CTF@CIT 2025"
  year: 2025
  challenge: "Calculator"
---

## Metadata

- **CTF:** CTF@CIT 2025
- **Task:** Calculator
- **Author team:** whoam!
- **CTFtime tags:** whitespace
- **CTFtime:** <https://ctftime.org/writeup/40210>
- **Original writeup:** <https://github.com/isip-hs-whoami/CTF-writeup/blob/main/CTF%40CIT%202025/Calculator/writeup.md>

---
# CTF@CIT - 2025  
###### Contributed by [@scott987](<https://github.com/scott987>)

## Calculator - 777 / MISC

> Find the flag.  
>  
> [calculator.lua](<https://raw.githubusercontent.com/isip-hs-whoami/CTF-writeup/refs/heads/main/CTF%40CIT%202025/Calculator/calculator.lua>)

### Solution  
The attached file has a .lua extension, indicating a Lua program. However, the source code contains more than just Lua syntax; it includes several lines composed of spaces and tabs after the code of lua.

![whitespace](<https://raw.githubusercontent.com/isip-hs-whoami/CTF-writeup/refs/heads/main/CTF%40CIT%202025/Calculator/whitespace.png>).

This pattern matches the characteristics of the [whitespace](<https://en.wikipedia.org/wiki/Whitespace_(programming_language)>)

Executing it with the [online interpreter](<https://naokikp.github.io/wsi/whitespace.html>), we get the flag: `CIT{hft4bT0415Lb}`
