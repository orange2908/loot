---
title: "Hidden Snack Stop - SwampCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "hidden", "snack", "stop", "swampctf", "swampctf-2024", "2024", "ctf-writeup"]
summary: "The flag is the address of this location as it’s shown on google maps."
source:
  name: "CTFtime writeup #39024"
  url: "https://ctftime.org/writeup/39024"
original_source: "https://margheritaviola.com/2024/04/08/swampctf-2024-osint-hidden-snack-stop-writeup/"
ctf:
  name: "SwampCTF 2024"
  year: 2024
  challenge: "Hidden Snack Stop"
---

## Metadata

- **CTF:** SwampCTF 2024
- **Task:** Hidden Snack Stop
- **Author team:** creeper
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/39024>
- **Original writeup:** <https://margheritaviola.com/2024/04/08/swampctf-2024-osint-hidden-snack-stop-writeup/>

---
> I found this really good chips place, but I don’t want it to be crowded, so I’ve blurred everything. Hahaha!  
The flag is the address of this location as it’s shown on google maps. Good luck!  
Do not wrap the address in swampCTF{}

![](<https://margheritaviola.com/wp-content/uploads/2024/04/image-11.png>)

There are two important clues in the image.  
![](<https://margheritaviola.com/wp-content/uploads/2024/04/Ekran-Resmi-2024-04-08-12.10.49.png>)  
![](<https://margheritaviola.com/wp-content/uploads/2024/04/image-12.png>)

If we investigate the first clue, we find Mountain Xpress. “Asheville and Western North Carolina News”. This gives us an idea to search for “Carolina” as a location. If we google the name of the hotel the second clue is “Elevation Hotel Carolina”. We’ll find the hotel and the location.  
![](<https://margheritaviola.com/wp-content/uploads/2024/04/image-13.png>)  
![](<https://margheritaviola.com/wp-content/uploads/2024/04/image-14.png>)

When we get to the location, we find The Gourmet Chip Company.  
[video link.](<https://margheritaviola.com/2024/04/08/swampctf-2024-osint-hidden-snack-stop-writeup/>)

```  
43 1/2 Broadway St, Asheville, NC 28801, United States  
```
