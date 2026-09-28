---
title: "Say My Name - CTF@CIT 2026"
category: "rev"
type: "writeup"
tags: ["rev", "say", "name", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Category: Reverse Engineering"
source:
  name: "CTFtime writeup #40749"
  url: "https://ctftime.org/writeup/40749"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Say My Name"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Say My Name
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40749>

---
# Writeup: Say My Name

\- Category: Reverse Engineering  
\- Value: 822 pts (179 solves)  
\- Author: ronnie  
\- Status: **SOLVED**

## Challenge

We are given a Linux ELF 64-bit statically linked executable named `saymyname`. The description just says "Say My Name!".

## Solution

Similar to the previous challenge, we can start with basic static analysis. We uploaded the binary to our remote dev box and ran `strings` on it, filtering for the flag format `CIT{`:

```bash  
strings saymyname | grep -i "CIT{"  
```

This immediately revealed the flag in plaintext as part of a success message: `yeah that me. heres your flag CIT{Zn583Umnwd4S}`. No further reverse engineering was needed.

## Flag

```text  
CIT{Zn583Umnwd4S}  
```
