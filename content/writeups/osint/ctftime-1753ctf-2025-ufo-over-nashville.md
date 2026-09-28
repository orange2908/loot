---
title: "UFO Over Nashville - 1753CTF 2025"
category: "osint"
type: "writeup"
tags: ["osint", "pie", "ufo", "nashville", "1753ctf", "1753ctf-2025", "2025", "ctf-writeup"]
summary: "\\- Video uploaded to Parler in Octover 2020, by Mark"
source:
  name: "CTFtime writeup #40167"
  url: "https://ctftime.org/writeup/40167"
ctf:
  name: "1753CTF 2025"
  year: 2025
  challenge: "UFO Over Nashville"
---

## Metadata

- **CTF:** 1753CTF 2025
- **Task:** UFO Over Nashville
- **Author team:** weareurs
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/40167>

---
# UFO Over Nashville

#osint 

## Clues

\- Video uploaded to Parler in Octover 2020, by Mark  
\- Less than a minute long and shows a "mesmerizing ufo spectacle"  
\- Video has a neon sign for a restaurant

We need to find a dish at the restaurant which costs $3

## Find the UFO video

I searched YouTube for "UFO Over Nashville Mark" and filtered the results for videos less than 4 minutes

![](<https://github.com/0x747/capture-the-flag/blob/main/1753ctf/screenshots/ufo-over-nashville/image.png?raw=true>)

Now this video is more than a minute long but it does have neon signs and a mesmerizing effect in the sky, so I decided to pursue the lead.

The neon sign says, "Robert's Western World"

## Find the menu at Robert's Western World

Searching for "Robert's Western World Nashville" we can find their website and see their [menu](<https://www.robertswesternworld.com/honky-tonk-grill>)

![](<https://github.com/0x747/capture-the-flag/blob/main/1753ctf/screenshots/ufo-over-nashville/image1.png?raw=true>)

The "Moonpie" costs $3 so I tried to use that but the flag was wrong. So I decided to look for other versions of the menu.

## Find other menus on Google Maps

Looking at the pictures of menu's on Google Maps we find:

![](<https://github.com/0x747/capture-the-flag/blob/main/1753ctf/screenshots/ufo-over-nashville/image2.png?raw=true>)

THERE'S A SPACE IN MOON PIE! Just to be sure I asked Mr. Fox on how to handle spaces in flag

Make sure to user an underscore in place of the space
