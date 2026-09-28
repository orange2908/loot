---
title: "Trackdown 2 - 1337UP LIVE CTF"
category: "osint"
type: "writeup"
tags: ["osint", "trackdown", "1337up-live-ctf", "ctf-writeup"]
summary: "Players receive the following image."
source:
  name: "CTFtime writeup #39680"
  url: "https://ctftime.org/writeup/39680"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "Trackdown 2"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** Trackdown 2
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/39680>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/>

---
Players receive the following image.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/original-photo.jpg>)

A bit harder than the last one, but there's a few approaches. You want to zoom in and look for anything with text, that you can search for on Google Maps. How about the `A25 HOTEL`?

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/a25-hotel-sign.jpg>)

Alternatively, could go for `Little HaNoi EGG COFFEE` or `THE SIMPLE CAFE`.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/nearby-cafes.jpg>)

I'm sure you can find plenty more! We just want to get the general area, I'll try `Little HaNoi EGG COFFEE` (I was going to post a pic taken from that balcony, but I think it was too hard to pinpoint from the view).

Unfortunately, there are a lot of results (it's a chain, albeit a small one) so let's start with [the default](<https://maps.app.goo.gl/e2aftjBVh55WyGfa8>) and look for a nearby `A25 Hotel`.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/maps-egg-coffee-search.jpg>)

Oh dear, there are a lot! The red arrow is the location of the `Litle HaNoi EGG COFFEE`.

Let's check for `SIMPLE CAFE`.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/simple-cafe-search.jpg>)

Nope, there should be one right next to the Egg Coffee shop! Some other ways we could verify this would be checking the satellite and street view imagery _or_ looking through the pictures of the coffee shop on Google Maps (there should be some of that nice balcony).

OK, let's revise our approach. I'll search for `little hanoi egg coffee` without moving the map.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/refined-maps-search.jpg>)

We could check all 3 (already checked `Yersin`) but let's think smart ? When we looked for directions to the `SIMPLE CAFE` it was an 11 minute walk away and _right next to_ the `Little Hanoi Egg Coffee` you see to the left of the `Yersin` store.

We [check it](<https://maps.app.goo.gl/gvHtrMDSaJ8Z4d5S9>) and the very first image is the balcony ?

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/egg-coffee-balcony.jpg>)

OK, lets think about the original image again. What do we see right in front of us?? That's right, buses ?

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/bus-station-view.jpg>)

There's the bus station!! See that hotel on the map? [Click on it](<https://maps.app.goo.gl/71QEUeetGeke2ErL6>) and look through the pictures. You'll see some that look familiar, e.g.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/express-by-m-village.jpg>)

Flag: `INTIGRITI{Express_by_M_Village}`

We allowed several variations of the location, not case-sensitive:

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/accepted-answers.png>)

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown2/images/final-reference-photo.jpg>)
