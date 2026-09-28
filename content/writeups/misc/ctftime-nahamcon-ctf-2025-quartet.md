---
title: "Quartet - NahamCon CTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "quartet", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "Four files are given with .z01 extension, running file command on them shows the following output :"
source:
  name: "CTFtime writeup #40275"
  url: "https://ctftime.org/writeup/40275"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/warmup/Quartet"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "Quartet"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** Quartet
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40275>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/warmup/Quartet>

---
> Solved by thewhiteh4t

Four files are given with `.z01` extension, running `file` command on them shows the following output : 

quartet.z01: Zip multi-volume archive data, at least PKZIP v2.50 to extract  
quartet.z02: data  
quartet.z03: data  
quartet.z04: Zip archive data, made by v3.0 UNIX, extract using at least v2.0, last modified, last modified Sun, May 10 2025 04:28:04, uncompressed size 2035495, method=deflate

Unzipping them leads to another file named `quartet.jpeg`. By running `strings` command on the image and grepping for flag string we can get the flag : 

strings quartet.jpeg | grep flag  
flag{8f667b09d0e821f4e14d59a8037eb376}

**Key Learning & Takeaways**

\- Run strings : You'd be surprised how often a flag or a crucial hint is just sitting there in plain text.  
\- Check the file type with file : A simple file command can tell you a lot about what you're dealing with. Knowing this helps you pick the right tools for the job.  
\- Keep an eye out for flag formats : Most CTFs use a consistent flag format (like `flag{...}`).
