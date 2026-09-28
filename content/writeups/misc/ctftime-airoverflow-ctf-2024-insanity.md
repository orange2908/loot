---
title: "Insanity - AirOverflow CTF - 2024"
category: "misc"
type: "writeup"
tags: ["misc", "cyberchef", "base64", "insanity", "airoverflow-ctf", "airoverflow-ctf-2024", "2024", "ctf-writeup"]
summary: "Challenge description is like below:"
source:
  name: "CTFtime writeup #39352"
  url: "https://ctftime.org/writeup/39352"
original_source: "https://medium.com/@embossdotar/ctf-writeup-airoverflow-ctf-2024-insanity-273d3d5d4128"
ctf:
  name: "AirOverflow CTF - 2024"
  year: 2024
  challenge: "Insanity"
---

## Metadata

- **CTF:** AirOverflow CTF - 2024
- **Task:** Insanity
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39352>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-airoverflow-ctf-2024-insanity-273d3d5d4128>

---
Hi All,

Challenge description is like below:  
"When creating this absolutely amazing therne (huehue), I  
(unintentionally) left a flag somewhere.  
I can't seem to find it either.  
Author: TheFlash2k"

(little disclaimer - used here browser feature 'Copy text from image', I hope no typos etc)

Indeed, really nice theme — great job! Scrolling down we can see the footer — “Theme designed by AirOverflow”.

Perhaps most of you will check the page’s source code, DevTools, make a manual recon etc. It is proper approach taking into account this kind of tip.

In general, results of typical ways to get a flag in case like this were ‘clear’ — empty of flag. With one exception.

Good handle was — check “[/sitemap.xml](<https://en.wikipedia.org/wiki/Site_map)”>. Thanks to this we can see view like this one:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*gcLjFRlTJM_zDr6Ur5OgdQ.png>)

Sitemap.xml view, source: AirOverflow CTF — 2024

O, wow. [Base64](<https://www.freecodecamp.org/news/what-is-base64-encoding/>), now all you need to do is decode and we have it! Nope. ⚡

But it’s time for little spoiler — we are still really close :P

![](<https://miro.medium.com/v2/resize:fit:626/format:webp/1*7r287wjTCovj1TlGzPvJqg.png>)

Decoded Base64 view — using CyberChef

On the one hand, it was slightly confusing. On the other hand, it is worth continuing to assume that we are close.

Go back to this site and… check the source code there! Search for “CTF{“.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*mq9wwqNsNGiSLSJ-W_NV1g.png>)

The flag — source: AirOverflow CTF — 2024

Flag: **AOFCTF{bu7_wh3r3_t0_pu7_7h1s?}**

I hope you enjoy!
