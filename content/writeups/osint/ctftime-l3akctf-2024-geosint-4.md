---
title: "Geosint-4 - L3akCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "geoguessr", "geosint-4", "l3akctf", "l3akctf-2024", "2024", "ctf-writeup"]
summary: "This last one was quite challenging, as it didn't have anything very recognisable."
source:
  name: "CTFtime writeup #39174"
  url: "https://ctftime.org/writeup/39174"
original_source: "https://github.com/hemiol14/writeups/blob/master/CTFs/L3akCTF2024/Geosint4.md"
ctf:
  name: "L3akCTF 2024"
  year: 2024
  challenge: "Geosint-4"
---

## Metadata

- **CTF:** L3akCTF 2024
- **Task:** Geosint-4
- **Author team:** alicel
- **CTFtime tags:** osint, geoguessr
- **CTFtime:** <https://ctftime.org/writeup/39174>
- **Original writeup:** <https://github.com/hemiol14/writeups/blob/master/CTFs/L3akCTF2024/Geosint4.md>

---
# Geosint 4 - L3akCTF 2024

This last one was quite challenging, as it didn't have anything very recognisable.

![initial image](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/geochall4_begin.png>)

Using this [geohints](<https://geohints.com/>) website, I confirmed that it looks like a european country that has tons of islands... like Greece. Google Lens also gave me some results in Greece, but nothing very promising. 

Eventually, I started looking for "\\[country\\] scenery roads" just to try to get a road similar to the one on the picture. Aaaannd.. I got lucky. 

![lucky search](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/geochall4_key.png>)

That [video on Youtube]([https://www.youtube.com/watch?app=desktop&v=ssYN9F9XcsI](https://www.youtube.com/watch?app=desktop&v=ssYN9F9XcsI)) was clearly recorded going through the same road, so I watched it. It says it goes from Vouliagmeni to Lavrio, and before minute 5 it goes through the road I was searching. Right after that, it leaves behind a restaurant name Alkyonides which I was able to find on Google Maps, hence getting the coordenates to beat the last game.

![alkyonides](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/geochall4_bar.png)!>[solution image](<https://github.com/hemiol14/writeups/raw/master/CTFs/L3akCTF2024/media/geochall4_solved.png>)

⭐️✨⭐️✨⭐️✨⭐️✨⭐️✨⭐️✨⭐️✨⭐️

> Flag: **L3AK{GrEeCe_R0@DTr1P!}**

⭐️✨⭐️✨⭐️✨⭐️✨⭐️✨⭐️✨⭐️✨⭐️
