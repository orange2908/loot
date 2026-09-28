---
title: "Read Only - CTF@CIT 2025"
category: "rev"
type: "writeup"
tags: ["rev", "read", "only", "ctf-cit", "ctf-cit-2025", "2025", "ctf-writeup"]
summary: "First, we use the \"strings\" command to find printable strings in the file:"
source:
  name: "CTFtime writeup #40238"
  url: "https://ctftime.org/writeup/40238"
original_source: "https://github.com/isip-hs-whoami/CTF-writeup/blob/main/CTF%40CIT%202025/Read%20Only/writeup.md"
ctf:
  name: "CTF@CIT 2025"
  year: 2025
  challenge: "Read Only"
---

## Metadata

- **CTF:** CTF@CIT 2025
- **Task:** Read Only
- **Author team:** whoam!
- **CTFtime:** <https://ctftime.org/writeup/40238>
- **Original writeup:** <https://github.com/isip-hs-whoami/CTF-writeup/blob/main/CTF%40CIT%202025/Read%20Only/writeup.md>

---
# CTF@CIT - 2025  
###### Contributed by [@scott987](<https://github.com/scott987>)

## Read Only - 534 / REV

> Here we go!  
>  
> [readonly](<https://raw.githubusercontent.com/isip-hs-whoami/CTF-writeup/refs/heads/main/CTF%40CIT%202025/Read%20Only/readonly>)

### Solution  
First, we use the "strings" command to find printable strings in the file:

![check strings](<https://raw.githubusercontent.com/isip-hs-whoami/CTF-writeup/refs/heads/main/CTF%40CIT%202025/Read%20Only/check_strings.png>)

So, the challenge title, "Read Only", hints that we should look for the .rodata section within the file:

![readelf .rodata](<https://raw.githubusercontent.com/isip-hs-whoami/CTF-writeup/refs/heads/main/CTF%40CIT%202025/Read%20Only/readelf_rodata.png>)
