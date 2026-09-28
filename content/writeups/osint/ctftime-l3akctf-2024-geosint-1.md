---
title: "Geosint 1 - L3akCTF 2024"
category: "osint"
type: "writeup"
tags: ["geoguessr", "osint", "geosint", "l3akctf", "l3akctf-2024", "2024", "ctf-writeup"]
summary: "The first thing we see that can be recognisable is the bridge in the far distance."
source:
  name: "CTFtime writeup #39172"
  url: "https://ctftime.org/writeup/39172"
original_source: "https://github.com/hemiol14/writeups/blob/master/CTFs/L3akCTF2024/Geosint1.md"
ctf:
  name: "L3akCTF 2024"
  year: 2024
  challenge: "Geosint 1"
---

## Metadata

- **CTF:** L3akCTF 2024
- **Task:** Geosint 1
- **Author team:** alicel
- **CTFtime tags:** geoguessr, osint
- **CTFtime:** <https://ctftime.org/writeup/39172>
- **Original writeup:** <https://github.com/hemiol14/writeups/blob/master/CTFs/L3akCTF2024/Geosint1.md>

---
# Geosint 1 - L3akCTF 2024

The first thing we see that can be recognisable is the bridge in the far distance.

![initial image](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/geochall1_initial.png>)

If we take a picture of that bridge and upload it to [Google Lens](<https://lens.google.com>), it will inmediatly tell us it's the Verrazzano-Narrows Bridge, in New York, US. *For lazy people: take a screenshot selecting an area > copy to clipboard > open google lens and paste it (press ctrl+v) there*

![google lens results](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/google_lens3.png>)

Ok so if we check it on [Google Maps](<https://maps.google.com>), and we move around trying to get the same image as in the challenge, we get that the solution is near the green area close to the bridge.

![verrazzano bridge](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/geochall1_verrazanobridge.png>)  
![solution image](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/geochall1_solution.png>)

⭐✨⭐✨⭐✨⭐✨⭐✨⭐✨⭐✨⭐

> Flag: **L3AK{Verr4zz4n0_Br1dge_1s_pR3tty_c00l}**

⭐✨⭐✨⭐✨⭐✨⭐✨⭐✨⭐✨⭐
