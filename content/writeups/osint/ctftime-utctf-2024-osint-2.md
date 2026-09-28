---
title: "OSINT 2 - UTCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "utctf", "utctf-2024", "2024", "ctf-writeup"]
summary: "Again going back to the linktr.ee I decide to dig more into the Twitter, which seems to contain a single tweet."
source:
  name: "CTFtime writeup #39084"
  url: "https://ctftime.org/writeup/39084"
original_source: "https://seall.dev/posts/utctf2024#osint-2"
ctf:
  name: "UTCTF 2024"
  year: 2024
  challenge: "OSINT 2"
---

## Metadata

- **CTF:** UTCTF 2024
- **Task:** OSINT 2
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39084>
- **Original writeup:** <https://seall.dev/posts/utctf2024#osint-2>

---
# OSINT 2  
> Can you find where the person you identified in the first challenge lives? Flag format is City,State,Zip. For example, if they live at UT Austin submit Austin,TX,78712.

Again going back to the [linktr.ee](http://linktr.ee) I decide to dig more into the Twitter, which seems to contain a single tweet.

`Won't be posting on here anymore, you can find me on Mastodon now!`

So, let's take a look at that [Mastodon account](https://mastodon.social/@coleminerton).

There's some posts! Including photos... One of which has alot of good information and likely near where he lives.

![gas.jpg](https://seall.dev/images/ctfs/utctf2024/gas.jpg)

There is a sign in the middle that says New Mexico Lottery, so thats the state.

There is a street sign in the background that says 'Cimarron Ave', where is that?

Looking for instances of Cimarron Ave in New Mexico I find the [closed down gas station]([https://www.google.com.au/maps/@36.8948197,-104.4409946,3a,88.5y,39.12h,83.95t/data=!3m9!1e1!3m7!1sjelWzB99-q42G81gC-oMvA!2e0!7i13312!8i6656!9m2!1b1!2i45?hl=en&entry=ttu](https://www.google.com.au/maps/@36.8948197,-104.4409946,3a,88.5y,39.12h,83.95t/data=!3m9!1e1!3m7!1sjelWzB99-q42G81gC-oMvA!2e0!7i13312!8i6656!9m2!1b1!2i45?hl=en&entry=ttu)) which has the same Bradley and circle insignia of the fuel pumps.

Flag: `Raton,NM,87740`
