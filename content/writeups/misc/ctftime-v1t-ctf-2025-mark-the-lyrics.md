---
title: "Mark The Lyrics - V1t CTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "mark", "lyrics", "v1t-ctf", "v1t-ctf-2025", "2025", "ctf-writeup"]
summary: "We are presented with a lyrics website featuring an embedded YouTube video."
source:
  name: "CTFtime writeup #40479"
  url: "https://ctftime.org/writeup/40479"
original_source: "https://ctf.dvzr.io/competitions/v1t-ctf-2025/mark-the-lyrics/"
ctf:
  name: "V1t CTF 2025"
  year: 2025
  challenge: "Mark The Lyrics"
---

## Metadata

- **CTF:** V1t CTF 2025
- **Task:** Mark The Lyrics
- **Author team:** CaptureTheFat
- **CTFtime:** <https://ctftime.org/writeup/40479>
- **Original writeup:** <https://ctf.dvzr.io/competitions/v1t-ctf-2025/mark-the-lyrics/>

---
## Connections

  * ⇩ http://tommytheduck.github.io/mckey/


## Recon

We are presented with a lyrics website featuring an embedded YouTube video.

![Landing page](https://ctf.dvzr.io/assets/files/v1t-ctf-2025/mark-the-lyrics/website.png)

Upon examining the source code, we notice that certain characters are wrapped within `<mark>` HTML elements.

```
    <mark>V</mark>erse <mark>1</mark>: Sơn Tùng M-<mark>T</mark>
```

The first marked characters are `V1T`, which suggests that the flag is composed of all the characters contained within the `<mark>` elements in the DOM.

## Exploitation

We can extract all the text contained within the `<mark>` elements using the browser’s developer tools and a simple JavaScript snippet:

```
    const marks = document.getElementsByTagName("mark");
    let flag = "";
    
    for (mark of marks) {
      flag += mark.innerText;
    }
    
    console.log(flag);
```

## Flag capture

After running the script, you will see the flag displayed in the console:

```
    Flag: V1T{MCK-pap-cool-ooh-yeah}
```

[← Back to V1t CTF 2025](https://ctf.dvzr.io/competitions/v1t-ctf-2025/)
