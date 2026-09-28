---
title: "Start Me Up - CTF@CIT 2026"
category: "forensics"
type: "writeup"
tags: ["forensics", "base64", "start", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The hint is persistence, so the first place to check in the reused backup is the user Startup folder:"
source:
  name: "CTFtime writeup #40737"
  url: "https://ctftime.org/writeup/40737"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Start Me Up"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Start Me Up
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40737>

---
# Start Me Up — Writeup

\- Category: Forensics  
\- Value: 1000  
\- Author: boom

## Challenge

> Are we dealing with TrickBot here or something? What's with the persistence?!  
>  
> Use the challenge.zip from "The click that may have fixed" to solve this challenge :)

## Recon

The hint is persistence, so the first place to check in the reused backup is the user Startup folder:

```text  
AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/  
```

That folder contains an odd file:

```text  
e9fje2.txt  
```

## Solve

The file contents are base64:

```text  
Q0lUe3N0NHJ0X20zX3VwX2kxMV9uM3Yzcl9zdDBwfQ==  
```

Decoding it gives the flag directly:

```text  
CIT{st4rt_m3_up_i11_n3v3r_st0p}  
```

## Flag

```text  
CIT{st4rt_m3_up_i11_n3v3r_st0p}  
```

## Files

\- [challenge.zip](files/challenge.zip)  
\- [[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py))  
\- [e9fje2.txt](other/e9fje2.txt)  
\- [e9fje2.decoded.txt](other/e9fje2.decoded.txt)
