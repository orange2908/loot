---
title: "SNAD - NahamCon CTF 2025"
category: "web"
type: "writeup"
tags: ["web", "snad", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "In this challenge the website is having interaction if we click the website sand particles will fall off."
source:
  name: "CTFtime writeup #40280"
  url: "https://ctftime.org/writeup/40280"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/web/SNAD"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "SNAD"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** SNAD
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40280>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/web/SNAD>

---
> Solved by Legend

In this challenge the website is having interaction if we click the website *sand* particles will fall off.  
I check the source code and found the code for this where specific points were mentioned which we needed to trigger.

Tried a bunch of things and also tried to access the flag using `checkFlag()` but it didn't work so again made a script which will inject the points where the code is looking for.

const targets = [  
{ x: 367, y: 238, hue: 0 },  
{ x: 412, y: 293, hue: 40 },  
{ x: 291, y: 314, hue: 60 },  
{ x: 392, y: 362, hue: 120 },  
{ x: 454, y: 319, hue: 240 },  
{ x: 349, y: 252, hue: 280 },  
{ x: 433, y: 301, hue: 320 }  
];  
  
for (let i = 0; i < targets.length; i++) {  
injectSand(targets[i].x, targets[i].y, targets[i].hue);  
}

Once the points are matched to where the code is expecting the checks are passed and flag is given.

![](<https://i.imgur.com/KLnhP7m.png>)

**Key Learning and Takeaways**

\- Always check the source code it often includes useful logic or hardcoded values.  
\- Interactive web challenges may hide important behavior in JavaScript; inspect scripts, not just HTML.  
\- Reverse-engineering how the frontend works can help you figure out how to trigger backend logic.
