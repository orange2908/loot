---
title: "Dusk Till Duck - V1t CTF 2025"
category: "osint"
type: "writeup"
tags: ["osint", "dusk", "till", "duck", "v1t-ctf", "v1t-ctf-2025", "2025", "ctf-writeup"]
summary: "Writeup Author: Duc(k) Nguyen (duke7012 a.k.a."
source:
  name: "CTFtime writeup #40471"
  url: "https://ctftime.org/writeup/40471"
ctf:
  name: "V1t CTF 2025"
  year: 2025
  challenge: "Dusk Till Duck"
---

## Metadata

- **CTF:** V1t CTF 2025
- **Task:** Dusk Till Duck
- **Author team:** UofUCyberSec
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/40471>

---
# V1tCTF 2025: Dusk Till Duck

Writeup Author: `Duc(k) Nguyen` (`duke7012` a.k.a. `Duke` a.k.a. `SubierThumb`)

## Description

* Challenge author: `unknown`  
* Category: `OSINT`  
* Point value: `100`

![Description](<https://i.imgur.com/sNZvZSA.png>)

> As the sun sets over a calm lake, a lone duck drifts across the fading light. The scene looks peaceful, but the park hides more than it seems. Can you figure out where this photo was taken before the night falls?  
>   
> Format: v1t{place_name}  
> > Example: v1t{Abc_Park}

File(s):

* [dusk_till_duck.jpg (Original link)](https://ctf.v1t.site/files/6e042844a8fc4b0fec9953bbcce02cf4/dusk_till_duck.jpg?token=eyJ1c2VyX2lkIjo3NTUsInRlYW1faWQiOjM2NywiZmlsZV9pZCI6MjJ9.aQm3oA.wOTddYfDGgBnW0iCTU2aWituOLM)

![Image](<https://i.imgur.com/jYG5XX8.jpeg>)

## Tools used

* [Google Lens (in Google Search)](https://lens.google/)

## Initial Analysis

When encountering an OSINT challenge of finding a place with a given picture, I first reverse-search the image using [Google Lens](https://lens.google/). Go to **Exact matches** to find the source of the image. Never forget our goal is to find _what park is in the picture_.

![Screenshot](<https://i.imgur.com/wwspJm0.png>)

Ignore the Reddit post (cuz somebody posted this image on Reddit asking for help for the CTF -- which is NOT cool at all...), the only link I found is the [original image post](<https://www.shutterstock.com/id/image-photo/stunning-evening-view-swimming-ducks-thames-1781586122?dd_referrer=https%3A%2F%2Fwww.google.com%2F>). It is a stock image for sale.

![Screenshot](<https://i.imgur.com/dtNxBmv.png>)

I tried to look at the photographer's [profile](<https://www.shutterstock.com/g/Jay+Thaker>). It seems like this park is in Canada, since he said that he is based in Canada. He had great photographs, by the way!

![Screenshot](<https://i.imgur.com/20uX8O8.png>)

However, looking at his other photos, there is no clue about this park, since he travels a lot!. I go back to the picture, look at the info and it says `Stunning evening view with swimming ducks in the Thames River`.

So I started searching for `Parks near Thames River in Canada`...

![Screenshot](<https://i.imgur.com/r3DEZ2P.png>)

There are tons of parks along the river. Usually, the park name should not be too long for a CTF, so I try some of the short names first. Luckily, as I reach the second name, it says correct. Quack quack.

## Solution

`v1t{Ivey-Park}`

## Rating  
_**Like**: It is extremely difficult to brute force in an OSINT challenge. I believe there is a better way to verify the location of the photo, but it is definitely not worth it for an 100-point challenge._
