---
title: "The Overseer - KnightCTF 2025"
category: "web"
type: "writeup"
tags: ["web", "overseer", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "What is the web-based server management tool that is used here?"
source:
  name: "CTFtime writeup #39820"
  url: "https://ctftime.org/writeup/39820"
original_source: "https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/The_Overseer.md"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "The Overseer"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** The Overseer
- **Author team:** Not_So_Intelligent
- **CTFtime:** <https://ctftime.org/writeup/39820>
- **Original writeup:** <https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/The_Overseer.md>

---
## The Overseer

What is the web-based server management tool that is used here?

## Steps

**1.** Filter out the `http` requests

**2.** We see the `http` requests as follows:

![cockpit](<https://github.com/user-attachments/assets/b900a854-15c8-4309-98e2-b81b2273dc02>)

**3.** We see that in the `Info` tab we see `login` access for something named `cockpit`

**4.** `cockpit` is a very popular web-based server management system. So, the flag is:

```bash  
KCTF{cockpit}  
```
