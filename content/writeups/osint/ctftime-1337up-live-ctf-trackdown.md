---
title: "Trackdown - 1337UP LIVE CTF"
category: "osint"
type: "writeup"
tags: ["osint", "trackdown", "1337up-live-ctf", "ctf-writeup"]
summary: "Players receive the following image."
source:
  name: "CTFtime writeup #39679"
  url: "https://ctftime.org/writeup/39679"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "Trackdown"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** Trackdown
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/39679>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown/>

---
Players receive the following image.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown/images/original-photo.jpg>)

An obvious approach is to search for `Gucci, Trang Tien Plaza` on [Google Maps](<https://maps.app.goo.gl/EZP5Fpi9GM139uuR8>). Check the street view to find the same angle.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown/images/google-maps-street-view.jpg>)

Now, spin around and what do we see?

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown/images/opposite-view-seating.jpg>)

If you look closely, you can see the same seating/tables. Let's check the map..

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown/images/google-maps-location.jpg>)

There we go! We find the [correct location](<https://maps.app.goo.gl/nyvSVbDtRJYejKZh7>). That was an easy one :D Terrible, rip-off bar BTW - do not recommend. There's an amazing place round the corner that does a _delicious_ pho cocktail!

Flag: `INTIGRITI{Si_Lounge_Hanoi}`

We allowed several variations of the location, not case-sensitive:

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/trackdown/images/accepted-answers.jpg>)

Note, a lot of people confused `what the photo is of` and `where the photo was taken from`.
