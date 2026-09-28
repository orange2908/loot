---
title: "WebTopia Challneges - N0PSctf"
category: "web"
subcategory: "pow"
type: "writeup"
tags: ["web", "proof-of-work", "webtopia", "challneges", "pow", "n0psctf", "ctf-writeup"]
summary: "Challenge Name: Press Me If You Can"
source:
  name: "CTFtime writeup #40265"
  url: "https://ctftime.org/writeup/40265"
ctf:
  name: "N0PSctf"
  challenge: "WebTopia Challneges"
---

## Metadata

- **CTF:** N0PSctf
- **Task:** WebTopia Challneges
- **Author team:** N0C715
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40265>

---
# N0PS CTF 2025 - Press Me If You Can

**Category**: WebTopia   
**Challenge Name**: Press Me If You Can   
**Flag**: ✅ `N0PS{W3l1_i7_w4S_Ju5T_F0r_Fun}`   
**Author**: Sto

\---

## Challenge Description

> "Stop chasing me!" said the button.   
> "We can't. It's our job," they answered.   
>   
> Trapped in WebTopia on a page with no way out — except the fleeing button.

Challenge URL: [<https://nopsctf-press-me-if-you-can.chals.io>](<https://nopsctf-press-me-if-you-can.chals.io>)

\---

## Initial Observation

Landing on the challenge page, I saw a playful UI with blinking eyes and a single button labeled:

> **"Press Me"**

But as I moved my mouse near it, the button would jump away. Here’s what the page looked like:

![Challenge UI](<https://i.ibb.co/ccFf9ZN2/Screenshot-from-2025-06-02-14-23-54.png>)

\---

## Source Code Analysis

The HTML included a `script.js` and `styles.css`:

### JavaScript logic:

\- The `mousemove` event constantly checks the cursor’s position.  
\- If the cursor gets close (`distance <= OFFSET`), the button’s position (`top` and `left`) is updated to flee.  
\- The button is also **disabled** by default via JS.

```js  
const btn = document.querySelector("button");  
const OFFSET = 100;

let endPoint = { x: innerWidth / 2, y: innerHeight * 2 / 3 };

addEventListener("mousemove", (e) => {  
const btnRect = btn.getBoundingClientRect();  
const angle = Math.atan2(e.y - endPoint.y, e.x - endPoint.x);  
const distance = Math.sqrt(  
Math.pow(e.x - endPoint.x, 2) + Math.pow(e.y - endPoint.y, 2)  
);

if (distance <= OFFSET) {  
endPoint = {  
x: OFFSET * -Math.cos(angle) + e.x,  
y: OFFSET * -Math.sin(angle) + e.y  
};  
}

btn.style.left = endPoint.x + "px";  
btn.style.top = endPoint.y + "px";

btn.disabled = true;  
});  
```

\---

## Realization

The logic is purely **front-end evasion**. The button is:

\- Moved on every mouse movement.  
\- Disabled to block forced clicks.  
\- Not protected server-side.

So if I could **stop the JS**, **reposition the button**, and **re-enable** it, the click would likely go through.

\---

## Bypassing the Button Evasion

I opened the **DevTools Console** and executed the following code block to neutralize the JavaScript behavior:

### ✅ Exploit Code

```js  
(() => {  
const btn = document.querySelector("button");  
window.onmousemove = null;  
document.onmousemove = null;  
document.body.onmousemove = null;  
btn.style.position = "static";  
btn.style.left = "unset";  
btn.style.top = "unset";  
btn.disabled = false;  
console.log("[*] Button unlocked. Clicking now...");  
btn.click();  
})();  
```

This script:

\- Removes all `mousemove` listeners.  
\- Resets the button’s position.  
\- Re-enables the button.  
\- Simulates a click.

\---

## Result

The button successfully submitted the form and revealed the flag:

![Flag Screenshot](<https://i.ibb.co/FZZ40v6/Screenshot-from-2025-06-02-14-30-26.png>)

\---

## Final Flag

```  
N0PS{W3l1_i7_w4S_Ju5T_F0r_Fun}  
```

\---
