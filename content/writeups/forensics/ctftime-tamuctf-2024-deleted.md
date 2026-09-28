---
title: "Deleted - TAMUctf 2024"
category: "forensics"
type: "writeup"
tags: ["forensics", "deleted", "tamuctf", "tamuctf-2024", "2024", "ctf-writeup"]
summary: "The file we are given is a .e01 which I loaded with Autopsy."
source:
  name: "CTFtime writeup #39088"
  url: "https://ctftime.org/writeup/39088"
original_source: "https://seall.dev/posts/tamuctf2024#deleted"
ctf:
  name: "TAMUctf 2024"
  year: 2024
  challenge: "Deleted"
---

## Metadata

- **CTF:** TAMUctf 2024
- **Task:** Deleted
- **Author team:** IrisSec
- **CTFtime:** <https://ctftime.org/writeup/39088>
- **Original writeup:** <https://seall.dev/posts/tamuctf2024#deleted>

---
# Deleted  
> We found this file and was told that it contains a flag within it. Can you find the flag?

The file we are given is a `.e01` which I loaded with [Autopsy](<https://www.autopsy.com/>).

Once I loaded the file, I checked the 'deleted files' section.

![autopsy.png](https://seall.dev/images/ctfs/tamuctf2024/autopsy.png)

Inside the file `zzooo.png` was the flag.

![deleted.png](https://seall.dev/images/ctfs/tamuctf2024/deleted.png)

Flag: `gigem{f0und_d3l3t3d_f1l3}`

**Special Thanks to warlocksmurf, was stuck on a Mac and couldn't grab Autopsy screenshots :<**
