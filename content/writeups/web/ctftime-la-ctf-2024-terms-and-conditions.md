---
title: "terms-and-conditions - LA CTF 2024"
category: "web"
type: "writeup"
tags: ["web", "burp", "terms-and-conditions", "la-ctf", "la-ctf-2024", "2024", "ctf-writeup"]
summary: "When visiting the site linked, we are shown a plain webpage with some rules and an accept button, but when we get close it moves away from our cursor."
source:
  name: "CTFtime writeup #39097"
  url: "https://ctftime.org/writeup/39097"
original_source: "https://seall.dev/posts/lactf2024#webterms-and-conditions-769-solves"
ctf:
  name: "LA CTF 2024"
  year: 2024
  challenge: "terms-and-conditions"
---

## Metadata

- **CTF:** LA CTF 2024
- **Task:** terms-and-conditions
- **Author team:** IrisSec
- **CTFtime:** <https://ctftime.org/writeup/39097>
- **Original writeup:** <https://seall.dev/posts/lactf2024#webterms-and-conditions-769-solves>

---
# terms-and-conditions  
> Welcome to LA CTF 2024! All you have to do is accept the terms and conditions and you get a flag!

When visiting the site linked, we are shown a plain webpage with some rules and an accept button, but when we get close it moves away from our cursor.

![tac-1.png](https://seall.dev/images/ctfs/lactf2024/tac-1.png)

The way I approach this is by using Burp Suite to remove the client side movement code so the button cannot move away. I do this by intercepting responses in Burp Suite and then editing the response before the browser loads it.

I specifically remove this portion of the JS:

```js  
window.addEventListener("mousemove", function (e) {  
mx = e.clientX;  
my = e.clientY;  
});  
```

Flag: `lactf{that_button_was_definitely_not_one_of_the_terms}`
