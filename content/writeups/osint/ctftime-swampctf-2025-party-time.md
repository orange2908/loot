---
title: "Party Time! - SwampCTF 2025"
category: "osint"
subcategory: "metadata"
type: "writeup"
tags: ["osint", "exif", "party", "time", "metadata", "swampctf", "swampctf-2025", "2025", "ctf-writeup"]
summary: "It is well-known that we can store the location in images."
source:
  name: "CTFtime writeup #40137"
  url: "https://ctftime.org/writeup/40137"
ctf:
  name: "SwampCTF 2025"
  year: 2025
  challenge: "Party Time!"
---

## Metadata

- **CTF:** SwampCTF 2025
- **Task:** Party Time!
- **Author team:** Raccoon Byte
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/40137>

---
# Approach  
It is well-known that we can store the location in images. It will be stored as EXIF. So we only need to obtain the location, in the form of latitude and longitude.

There are many ways to do this, but my approach is to use [Online EXIF Viewer](<https://onlineexifviewer.com/>) to view the GPS coordinate. You can also use image viewer to do this.

One tricky is that the flag does not accept integer sign. So, after getting the coordinate, make sure you remove the sign, and that should be it.  
​  
# Answer  
​  
\- Photo GPS Location: 29.652866666666664,-82.33324444444445  
\- Flag: `swampCTF{29.65,82.33}`
