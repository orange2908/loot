---
title: "offtheramp - DownUnderCTF 2024"
category: "stego"
subcategory: "metadata"
type: "writeup"
tags: ["stego", "exiftool", "offtheramp", "metadata", "downunderctf", "downunderctf-2024", "2024", "ctf-writeup"]
summary: "We can see in the photo some cloudy day, or just a little bit blue sky with clouds."
source:
  name: "CTFtime writeup #39333"
  url: "https://ctftime.org/writeup/39333"
original_source: "https://medium.com/@embossdotar/ctf-writeup-downunderctf-2024-offtheramp-63cb06bdc6c7"
ctf:
  name: "DownUnderCTF 2024"
  year: 2024
  challenge: "offtheramp"
---

## Metadata

- **CTF:** DownUnderCTF 2024
- **Task:** offtheramp
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39333>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-downunderctf-2024-offtheramp-63cb06bdc6c7>

---
Hi All,

We can see in the photo some cloudy day, or just a little bit blue sky with clouds. Next, there is some sea or lake, cars in the parking lot. The photo could have been taken from the road while traveling:

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*0_TyViSeN7MNPJc0DfWtgQ.png>)

Image from the attachment, source: DownUnderCTF 2024 — offtheramp

This is OSINT challenge. One of the first steps as an action, could be checking metadata of this file.

You can make this in many ways, ie.: with the [Exiftool](<https://github.com/exiftool/exiftool>) or <https://exifinfo.org/>

We’re lucky! Data not erased:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*vcI22ojDKr3ZcX7m2d4sgw.png>)

Exiftool results, source: DownUnderCTF 2024

GPS coordinates are a strong ‘handle’ for us.

To convert the given GPS coordinates to a format that can be used with Google Maps and similar services, you need to convert [the degrees, minutes, and seconds (DMS) format](<https://en.wikipedia.org/wiki/Degree_(angle)>) to [decimal degrees (DD)](<https://en.wikipedia.org/wiki/Decimal_degrees>). Here’s how you can do it:

Given Coordinates  
Latitude: 38 degrees 9' 15.95" S  
Longitude: 145 degrees 6' 29.69" E  
Conversion Formula  
The formula to convert DMS to DD is:

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*joR6UYGkdLHWTIt5IcFgAQ.png>)

Latitude Conversion  
Degrees: 38  
Minutes: 9  
Seconds: 15.95

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*UK7lsV2eHoDvhm37TgLBlg.png>)

Since the latitude is South, it will be negative:

![](<https://miro.medium.com/v2/resize:fit:626/format:webp/1*8G-2g95YetI88PqL8mUr2g.png>)

Longitude Conversion  
Degrees: 145  
Minutes: 6  
Seconds: 29.69

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*EkBy2LIRqlbPDSRn89yVxA.png>)

Since the longitude is East, it will be positive:

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*38L46aqahsg9R9VCGcX9tQ.png>)

Final Coordinates for Google Maps  
Latitude: -38.15443056  
Longitude: 145.10824722

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*BjgGUlURMcS5c8HIULgHZQ.png>)

Almost the final answer! Source: DownUnderCTF 2024 & Google Maps

Taking into account the perspective, it looks very promising!

The title is a hint to get proper name of this structure (keyword: ramp).

Flag — solution: **DUCTF{olivers_hill_boat_ramp}**

I hope you enjoy!
