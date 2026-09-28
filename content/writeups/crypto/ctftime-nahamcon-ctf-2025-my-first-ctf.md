---
title: "My First CTF - NahamCon CTF 2025"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "cyberchef", "first", "classical", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "We get through to a \"rotten app\" with no JS, links, cookies or anything for us to explore!"
source:
  name: "CTFtime writeup #40298"
  url: "https://ctftime.org/writeup/40298"
original_source: "https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_first_ctf/"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "My First CTF"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** My First CTF
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/40298>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_first_ctf/>

---
We get through to a "rotten app" with no JS, links, cookies or anything for us to explore!

![](<https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_first_ctf/images/rotten-app-landing-page.png>)

The challenge description provided a hint; `Nz Gjstu DUG` is `My First CTF` rotated by 1 (caeser cipher). We can try and [ROT1]([https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,1)&input=ZmxhZy50eHQ](https://gchq.github.io/CyberChef/#recipe=ROT13\(true,true,false,1\)&input=ZmxhZy50eHQ)) some endpoints, e.g. `/admin`, `/flag` and eventually find the correct one is `/flag.txt`

We try the endpoint `/gmbh.uyu` and receive the flag.

Flag: `flag{b67779a5cfca7f1dd120a075a633afe9}`
