---
title: "Aerial Attack - SwampCTF 2024"
category: "osint"
subcategory: "metadata"
type: "writeup"
tags: ["osint", "exiftool", "aerial", "attack", "metadata", "swampctf", "swampctf-2024", "2024", "ctf-writeup"]
summary: "The flag is the truncated coordinate of this location to the hundredths."
source:
  name: "CTFtime writeup #39023"
  url: "https://ctftime.org/writeup/39023"
original_source: "https://margheritaviola.com/2024/04/08/swampctf-2024-osint-aerial-attack-writeup/"
ctf:
  name: "SwampCTF 2024"
  year: 2024
  challenge: "Aerial Attack"
---

## Metadata

- **CTF:** SwampCTF 2024
- **Task:** Aerial Attack
- **Author team:** creeper
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/39023>
- **Original writeup:** <https://margheritaviola.com/2024/04/08/swampctf-2024-osint-aerial-attack-writeup/>

---
> Find where this photo was taken! Make sure to keep your eyes out for the hawks though!  
The flag is the truncated coordinate of this location to the hundredths. For example: (xx.xx, xx.xx)

![](<https://margheritaviola.com/wp-content/uploads/2024/04/HawkChall-1-1-scaled.jpg>)

Since we are asked for image coordinates, we add the file to Exiftool. Find here the GPSLatitude and GPSLongitude coordinates of the image  
![](<https://margheritaviola.com/wp-content/uploads/2024/04/Ekran-Resmi-2024-04-08-11.43.04.png>)

If we enter these coordinates via [gps-coordinates.net](http://gps-coordinates.net), we will reach the flag.  
![](<https://margheritaviola.com/wp-content/uploads/2024/04/image-10.png>)
