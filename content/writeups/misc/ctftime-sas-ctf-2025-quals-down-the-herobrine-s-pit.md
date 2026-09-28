---
title: "Down the Herobrine's Pit - SAS CTF 2025 Quals"
category: "misc"
type: "writeup"
tags: ["misc", "minecraft", "down", "herobrine", "pit", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "When you loaded in to the server, you had to create an account and you'd get a Plotme plot (cannot build outside of 300x300-ish plot)."
source:
  name: "CTFtime writeup #40320"
  url: "https://ctftime.org/writeup/40320"
original_source: "https://github.com/looy3/ctf-writeups/blob/main/SASCTF/minecraft/down_the_herobrines_pit.md"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Down the Herobrine's Pit"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Down the Herobrine's Pit
- **Author team:** Team14
- **CTFtime tags:** minecraft
- **CTFtime:** <https://ctftime.org/writeup/40320>
- **Original writeup:** <https://github.com/looy3/ctf-writeups/blob/main/SASCTF/minecraft/down_the_herobrines_pit.md>

---
When you loaded in to the server, you had to create an account and you'd get a Plotme plot (cannot build outside of 300x300-ish plot). Huh, cool. Not every day you see a login system ON THE SERVER. Maybe you had to crack it? Nope. I was given 2 logs and a 1x1 hole to crawl into. Easy enough. I made a fence gate and crafting table and got through. I crawled until I found a chest FULL of trapdoors. Ok, that's useful for crawling. Continuing down the cave, I used trap doors for a bit before I realize this thing was never ending. 

Ok, I booted up a modded client. The server had cheat prevention tools. That's annoying! ESP showed me the entire map was a MASSIVE maze with a chest at the very bottom. What a cool opportunity for a frustrating red herring! Haha, nope. 

What I learned  
Pretty much nothing. I did it by hand, using ESP to confirm if a route was a deadend or not. I guess... if something?

Use modded clients  
Don't play dumb CTF challenges  
This is an example of a CTF challenge which can be done by hand (thereby dissuading more intelligent solutions). The creator of this challenge said you were supposed to use path finding algorithms to solve it. But that was unnecessary. Challenges like this would ideally be herculean in difficulty, in my opinion. Here is the flag:
