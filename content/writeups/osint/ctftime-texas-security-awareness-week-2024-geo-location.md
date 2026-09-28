---
title: "Geo-Location - Texas Security Awareness Week 2024"
category: "osint"
type: "writeup"
tags: ["osint", "geo-location", "texas-security-awareness-week", "texas-security-awareness-week-2024", "2024", "ctf-writeup"]
summary: "Find what street this picture was taken from."
source:
  name: "CTFtime writeup #38957"
  url: "https://ctftime.org/writeup/38957"
original_source: "https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/osint/geo-location.html"
ctf:
  name: "Texas Security Awareness Week 2024"
  year: 2024
  challenge: "Geo-Location"
---

## Metadata

- **CTF:** Texas Security Awareness Week 2024
- **Task:** Geo-Location
- **Author team:** reCAPTCHA the Flag
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/38957>
- **Original writeup:** <https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/osint/geo-location.html>

---
Find what street this picture was taken from. 

Format the flag as the following: The street name in all caps with the spaces replaced by underscores. 

Example: If the street was Bourbon Street the flag would be: texsaw{BOURBON_STREET} 

[picture.jpg](<https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Texsaw-CTF-2024/picture.jpg>) 

\---

Do a Google Reverse Image Search, drawing a rectangle area including only the most prominent building. Going to "Exact Matches", you'll find a building called TCC Legacy Kincaid. Searching it up will provide us an address. Move around the address in Google Street View until you find the Beal Bank sign, and thus the road it was taken from -- Legacy Dr! 

texsaw{LEGACY_DRIVE}
