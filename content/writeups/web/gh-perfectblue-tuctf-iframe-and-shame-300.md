---
title: "iFrame and shame 300 - tuctf 2017"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "command-injection", "iframe", "shame", "rce", "web-exploitation"]
summary: "We do some basic command injection."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2017/tuctf-2017/iFrame-and-shame-300/README.md"
ctf:
  name: "tuctf"
  year: 2017
  challenge: "iFrame and shame 300"
---

## Source

- **CTF:** tuctf 2017
- **Challenge:** iFrame and shame 300
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2017/tuctf-2017/iFrame-and-shame-300/README.md>

---
# iFrame and Shame
300 points

64 solves

>I overheard some guys bragging about how they have a custom Youtube search bar on their site. Put them to shame.
>
>Note: The input from the search bar should be passed to a script that queries youtube using "youtube.com/results?search_query=[your query]". Then it will put it in an iframe. You are only seeing the one video because it is the default upon error.
>NOTE: iFrame and Shame's search bar is supposed to query Youtube, but it doesn't behave as intended because we didn't consider that Youtube limits queries. The challenge is still solvable.
>	
>[http://iframeshame.tuctf.com](http://iframeshame.tuctf.com)

We do some basic command injection. It seems like catting the entire flag will make it break, but `";head -1 flag;"` works. `TUCTF{D0nt_Th1nk_H4x0r$_C4nt_3sc4p3_Y0ur_Pr0t3ct10ns}`

Solved by Jazzy
