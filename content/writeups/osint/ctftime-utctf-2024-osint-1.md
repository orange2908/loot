---
title: "OSINT 1 - UTCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "utctf", "utctf-2024", "2024", "ctf-writeup"]
summary: "We start with a fairly standard corporate website."
source:
  name: "CTFtime writeup #39083"
  url: "https://ctftime.org/writeup/39083"
original_source: "https://seall.dev/posts/utctf2024#osint-1"
ctf:
  name: "UTCTF 2024"
  year: 2024
  challenge: "OSINT 1"
---

## Metadata

- **CTF:** UTCTF 2024
- **Task:** OSINT 1
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39083>
- **Original writeup:** <https://seall.dev/posts/utctf2024#osint-1>

---
# OSINT 1  
> It seems like companies have document leaks all the time nowadays. I wonder if this company has any.

We start with a fairly standard corporate website.

![osint1.png](https://seall.dev/images/ctfs/utctf2024/osint1.png)

Looking through the only part of particular interest seems to be the employees list. The user that catches my eye the most is a 'Cole Minerton' due to the little blurb under him being the most expansive and also a mention of 'social media presence'.

At the top of the results is a [Twitter account](<https://twitter.com/coleminerton>) which has a [[linktr.ee](http://linktr.ee)](<https://linktr.ee/coleminerton>) attached!

Browsing his social media I can see that he has a [YouTube channel](<https://www.youtube.com/channel/UCkdrU8xdCgL0oasGsZAlUpw>) which I saw below the Twitter in the search results so I go to it first.

Looking at the channel description there is a [Discord invite](<https://discord.gg/re9ez8ey>) which contains a conversation between Cole and his friends. Reading the conversation there is a file posted, a `trustly-contract.pdf`.

Downloading the file and reading it contains the flag.

Flag: `utflag{discord_is_my_favorite_document_leaking_service}`
