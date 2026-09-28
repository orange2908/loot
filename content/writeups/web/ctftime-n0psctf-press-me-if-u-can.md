---
title: "Press Me If U Can - N0PSctf"
category: "web"
type: "writeup"
tags: ["web", "press", "n0psctf", "ctf-writeup"]
summary: "We start on a page with a Press Me button, that moves when you get too close to it with your mouse."
source:
  name: "CTFtime writeup #40302"
  url: "https://ctftime.org/writeup/40302"
original_source: "https://cryptocat.me/blog/ctf/2025/nops/web/press_me_if_you_can/"
ctf:
  name: "N0PSctf"
  challenge: "Press Me If U Can"
---

## Metadata

- **CTF:** N0PSctf
- **Task:** Press Me If U Can
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/40302>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2025/nops/web/press_me_if_you_can/>

---
We start on a page with a `Press Me` button, that moves when you get too close to it with your mouse. The eyes follow too, cute!

![](<https://cryptocat.me/blog/ctf/2025/nops/web/press_me_if_you_can/images/press-me-button.png>)

The JS contains all the logic for the animation, movement etc. That's not too important though, we just need to click the button so should find it's declaration.  
```js  
const btn = document.querySelector("button");  
```

Later in the script, it is disabled.  
```js  
btn.disabled = true;  
```

We can modify these properties from the browser console, and click the button.  
```js  
btn.disabled = false;  
btn.click();  
```

A POST request is issued, and the response contains our flag (displayed in the console log).

Flag: `N0PS{W3l1_i7_w4S_Ju5T_F0r_Fun}`
