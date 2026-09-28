---
title: "Tiny Flag - V1t CTF 2025"
category: "web"
type: "writeup"
tags: ["web", "tiny", "v1t-ctf", "v1t-ctf-2025", "2025", "ctf-writeup"]
summary: "Writeup Author: Duc(k) Nguyen (duke7012 a.k.a."
source:
  name: "CTFtime writeup #40474"
  url: "https://ctftime.org/writeup/40474"
ctf:
  name: "V1t CTF 2025"
  year: 2025
  challenge: "Tiny Flag"
---

## Metadata

- **CTF:** V1t CTF 2025
- **Task:** Tiny Flag
- **Author team:** UofUCyberSec
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40474>

---
# V1tCTF 2025: Tiny Flag

Writeup Author: `Duc(k) Nguyen` (`duke7012` a.k.a. `Duke` a.k.a. `SubierThumb`)

## Description

* Challenge author: `unknown`  
* Category: `Web`  
* Point value: `100`

![Description](<https://i.imgur.com/0VfthNh.png>)

> Do you see the tiny flag :>  
>   
> <https://tommytheduck.github.io/tiny_flag/>

Website(s):

* <https://tommytheduck.github.io/tiny_flag/>

## Tools used

* Google Chrome  
* _Alternative:_ Any browser with the inspection feature.

## Initial Analysis

The website is mostly blank. I tried to highlight the empty space in the middle, and got this text: `Tiny flag — look closely ✨`. However, this text looks normal. I tried some stegnographic decoder, but I just realized that this is a Web challenge, so nothing to do with stegno.

![Screenshot](<https://i.imgur.com/bK025pR.png>)

When I look at the website again, I saw the word `Inspect me` in the middle of the website, so I tried to inspect it.

![Screenshot](<https://i.imgur.com/7jbhDRT.png>)

There is nothing seemed weird to me, so I decided to press all the links available in the HTML code, to make sure nothing is hidden in the files. As I pressed to the very first link `favicon.ico`, the website icon file, I saw something weird...

![Screenshot](<https://i.imgur.com/Uihs34v.png>)

It looks like a text... Let's zoom it in...

![Screenshot](<https://i.imgur.com/2YZFQNo.png>)

No doubt! It's a flag! Quack quack.

## Solution

`v1t{T1NY_ICO}`

## Rating  
_**Like**: Cool challenge for Web beginner! Also, MCK is a famous rapper in Vietnam, so if you are interested, you can find more songs from him online :D_
