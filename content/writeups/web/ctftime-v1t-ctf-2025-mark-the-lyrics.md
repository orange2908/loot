---
title: "Mark The Lyrics - V1t CTF 2025"
category: "web"
type: "writeup"
tags: ["web", "mark", "lyrics", "v1t-ctf", "v1t-ctf-2025", "2025", "ctf-writeup"]
summary: "Writeup Author: Duc(k) Nguyen (duke7012 a.k.a."
source:
  name: "CTFtime writeup #40472"
  url: "https://ctftime.org/writeup/40472"
ctf:
  name: "V1t CTF 2025"
  year: 2025
  challenge: "Mark The Lyrics"
---

## Metadata

- **CTF:** V1t CTF 2025
- **Task:** Mark The Lyrics
- **Author team:** UofUCyberSec
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40472>

---
# V1tCTF 2025: Mark The Lyrics

Writeup Author: `Duc(k) Nguyen` (`duke7012` a.k.a. `Duke` a.k.a. `SubierThumb`)

## Description

* Challenge author: `MCK`  
* Category: `Web`  
* Point value: `100`

![Description](<https://i.imgur.com/NEM1SA8.png>)

> My friend make a website for his favourite, but the lyrics seem a little bit odd  
>   
> <http://tommytheduck.github.io/mckey>

Website(s):

* <http://tommytheduck.github.io/mckey>

## Tools used

* Google Chrome  
* _Alternative:_ Any browser with the inspection feature.

## Initial Analysis

The website looks very normal, just a webpage displaying the lyrics of a remix music video. I am Vietnamese, so I know where most parts of the lyrics come from. It was really dope, you should listen to it!

![Screenshot](<https://i.imgur.com/zewIVvj.png>)

Anyway, first thing first, I did not have many experience with Web challenges, so the only first thing I could do is to **Inspect** it!

![Screenshot](<https://i.imgur.com/6vjabuY.png>)

As I expand the very first line of the lyric, there is something very noticable here. The letter `V`, `1` and `T` are visibly used the `<mark>` tag, which is very suspicious since those are the letters of the flag format.

![Screenshot](<https://i.imgur.com/WPgYuF2.png>)

That's why I decided to unfold all of the lyrics line to find the marked words. I found the following words are using the same tag: `MCK`, `-pap-`, `cool`, `-ooh-`, `yeah` and `}`. It is quite funny because they missed the the opening curly brace, but it is enough for you to recognize that it is our flag.

Quack quack.

## Solution

`v1t{MCK-pap-cool-ooh-yeah}`

## Rating  
_**Like**: Cool challenge for Web beginner! Also, MCK is a famous rapper in Vietnam, so if you are interested, you can find more songs from him online :D_
