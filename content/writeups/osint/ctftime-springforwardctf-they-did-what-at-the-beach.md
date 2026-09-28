---
title: "they-did-WHAT-at-the-beach - SpringForwardCTF"
category: "osint"
type: "writeup"
tags: ["osint", "they-did-what-at-the-beach", "springforwardctf", "ctf-writeup"]
summary: "Since the CTF was based around greek mythology, I guessed that it had something to do with a greek god."
source:
  name: "CTFtime writeup #39114"
  url: "https://ctftime.org/writeup/39114"
ctf:
  name: "SpringForwardCTF"
  challenge: "they-did-WHAT-at-the-beach"
---

## Metadata

- **CTF:** SpringForwardCTF
- **Task:** they-did-WHAT-at-the-beach
- **Author team:** g00fy_ahh
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/39114>

---
Since the CTF was based around greek mythology, I guessed that it had something to do with a greek god.  
A quick search gives the result of Aphrodite, who was conceived at the sea from Uranus's castrated testicles.

Since the flag format was nicc{daughter_father}, I first tried nicc{Aphrodite_Uranus}. However, it wasn't accepted.

Reading the hint, it says "There are many different spellings, but only one right answer. So try 'em all."

The correct flag ended up being nicc{Aphrodite_Ouranos}, with ouranos being an alternate name for uranus.
