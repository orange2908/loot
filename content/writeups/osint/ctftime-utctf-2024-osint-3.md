---
title: "OSINT 3 - UTCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "utctf", "utctf-2024", "2024", "ctf-writeup"]
summary: "Now initially this one seems a bit trickier, where would we find an IP aside from something like a data breach?"
source:
  name: "CTFtime writeup #39085"
  url: "https://ctftime.org/writeup/39085"
original_source: "https://seall.dev/posts/utctf2024#osint-3"
ctf:
  name: "UTCTF 2024"
  year: 2024
  challenge: "OSINT 3"
---

## Metadata

- **CTF:** UTCTF 2024
- **Task:** OSINT 3
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39085>
- **Original writeup:** <https://seall.dev/posts/utctf2024#osint-3>

---
# OSINT 3  
> Can you find the person's IP address? Flag format is [XXX.XXX.XXX.XXX](http://XXX.XXX.XXX.XXX)

Now initially this one seems a bit trickier, where would we find an IP aside from something like a data breach?

Let's browse the remaining social media from the [linktr.ee](http://linktr.ee). I decide to take a closer look at the remaining social media, [Reddit](<https://old.reddit.com/user/coleminerton>).

Looking at the Reddit we can see he is a new moderator for the `r/tinyislandsurvival` subreddit, and on his YouTube in his only video, the comments show him mentioning the game as well so it must have some importance.

I look at the `r/tinyislandsurvival` sudreddit and see a wiki page attached, and I have an idea. On alot of Wiki's it is common when you are unauthenticated that commits use your IP address.

On the Fandom page I hover over the three dots in the top left and click 'View history', and ofcourse Cole is there. Scrolling on the commits we can see a particular set.

![osint3.png](https://seall.dev/images/ctfs/utctf2024/osint3.png)

Flag: `181.41.206.31`
