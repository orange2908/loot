---
title: "Affekot - snakeCTF 2024 Quals"
category: "web"
type: "writeup"
tags: ["web", "nextjs", "burp", "affekot", "snakectf-2024-quals", "2024", "ctf-writeup"]
summary: "Some of the web application's URL paths were disclosed in the script files (I used JS Link Finder burp suite extension) and were publicly accessible (/dev/signup and /dev/signin)."
source:
  name: "CTFtime writeup #39450"
  url: "https://ctftime.org/writeup/39450"
original_source: "https://www.thesecuritywind.com/post/small-winds-no-03#viewer-8apex36146"
ctf:
  name: "snakeCTF 2024 Quals"
  year: 2024
  challenge: "Affekot"
---

## Metadata

- **CTF:** snakeCTF 2024 Quals
- **Task:** Affekot
- **Author team:** WindTeam
- **CTFtime tags:** nextjs
- **CTFtime:** <https://ctftime.org/writeup/39450>
- **Original writeup:** <https://www.thesecuritywind.com/post/small-winds-no-03#viewer-8apex36146>

---
### Description:   
> Affekot  
>   
> 50  
>   
>   
> I really want to buy the flag, but it's out of stock!  
>   
> I heard that the admin took the last one...

### Solution:  
Some of the web application's URL paths were disclosed in the script files (I used JS Link Finder burp suite extension) and were publicly accessible (/dev/signup and /dev/signin). Using these, we could register and log in as an admin user and read the flag, which existed in the 'orders' API endpoint.
