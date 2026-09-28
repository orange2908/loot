---
title: "Hidden Message-Board - SwampCTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "hidden", "message-board", "swampctf", "swampctf-2025", "2025", "ctf-writeup"]
summary: "There is a clue to the flag in the task description: Nothing has worked so far but we have noticed a weird comment in the HTML."
source:
  name: "CTFtime writeup #40138"
  url: "https://ctftime.org/writeup/40138"
ctf:
  name: "SwampCTF 2025"
  year: 2025
  challenge: "Hidden Message-Board"
---

## Metadata

- **CTF:** SwampCTF 2025
- **Task:** Hidden Message-Board
- **Author team:** Raccoon Byte
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40138>

---
# Approach  
There is a clue to the flag in the task description: `Nothing has worked so far but we have noticed a weird comment in the HTML.`

When we inspect the website's element, we will find a hidden element:  
```html  
<div style="display: none;">Need to remove flagstuff. code: G1v3M3Th3Fl@g!!!!</div>  
```

Just above that, there's a `div` tag:  
```html  
<div id="flagstuff" code=""></div>  
```

It turns out that we need to fill in the `code` to the `div` tag. So, change the `div` tag to something like this:  
```html  
<div id="flagstuff" code="G1v3M3Th3Fl@g!!!!"></div>  
```

Then, we only need to type in at the provided `textarea`.

# Answer

\- Flag: `swampCTF{Cr0ss_S1t3_Scr1pt1ng_0r_XSS_c4n_ch4ng3_w3bs1t3s}`
