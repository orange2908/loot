---
title: "Knight Shop Again - KnightCTF 2026"
category: "web"
type: "writeup"
tags: ["web", "knightctf2026", "knightctf", "burp", "knight", "shop", "again", "knightctf-2026", "2026", "ctf-writeup"]
summary: "A modern e-commerce platform for medieval equipment."
source:
  name: "CTFtime writeup #40531"
  url: "https://ctftime.org/writeup/40531"
original_source: "https://swarnimbandekar.github.io/knightctf26/"
ctf:
  name: "KnightCTF 2026"
  year: 2026
  challenge: "Knight Shop Again"
---

## Metadata

- **CTF:** KnightCTF 2026
- **Task:** Knight Shop Again
- **Author team:** TrickedMyAunty
- **CTFtime tags:** web, knightctf2026, knightctf
- **CTFtime:** <https://ctftime.org/writeup/40531>
- **Original writeup:** <https://swarnimbandekar.github.io/knightctf26/>

---
## Knight Shop Again

**Category:** Web 

### Challenge Description  
A modern e-commerce platform for medieval equipment. I know you'll figure it out.

Flag Format:- KCTF{Fl4g_heR3}

**URL**  
http://23.239.26.112:8087/

### Solution

\- website had a register page, so I registered a account.  
![dashboard](<https://hackmd.io/_uploads/S1Lkj018-g.png>)

\- now i saw a list of itmes being listed but i had only 50 dollars so all items costs 50+ dollars, so now I tried adding an item to the card but changed the quantity to `-1` in burpsuite.  
![addcart](<https://hackmd.io/_uploads/r1hlsAJ8Zg.png>)  
![cart](<https://hackmd.io/_uploads/ByQZsRy8bx.png>)

\- now i was able to make a purchase, i tried to buy it and then saw the response which had the flag.  
![flag](<https://hackmd.io/_uploads/Bk6biRyUWe.png>)

### Flag  
**KCTF{REDACTED}**
