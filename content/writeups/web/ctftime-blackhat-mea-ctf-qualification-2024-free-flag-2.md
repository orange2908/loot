---
title: "Free Flag - BlackHat MEA CTF Qualification 2024"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["ilyshoaib", "lfi", "freeflag", "web", "bhmea24", "php-filter", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "In this challenge, we identified a Local File Disclosure (LFD) vulnerability."
source:
  name: "CTFtime writeup #39430"
  url: "https://ctftime.org/writeup/39430"
original_source: "https://ilyshoaib.medium.com/writeup-blackhat-mea-qualification-ctf-2024-free-flag-110-a6482cf61128"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Free Flag"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Free Flag
- **Author team:** B A N D I T S - V I I
- **CTFtime tags:** ilyshoaib, lfi, freeflag, web, bhmea24
- **CTFtime:** <https://ctftime.org/writeup/39430>
- **Original writeup:** <https://ilyshoaib.medium.com/writeup-blackhat-mea-qualification-ctf-2024-free-flag-110-a6482cf61128>

---
![](<https://miro.medium.com/v2/resize:fit:828/format:webp/1*hDyqvgfsBSJ3yuRgAPb1hw.png>)

In this challenge, we identified a Local File Disclosure (LFD) vulnerability. The goal was to retrieve the flag from the server, but there were restrictions in place that blocked direct access to files.  
After reviewing the source code, we found a basic PHP script that allows specifying a filename to access files on the local system.  
# Exploitation  
I crafted the payload using a tool called [`php_filter_chain_generator`](<https://github.com/synacktiv/php_filter_chain_generator>). This tool helped generate the necessary filter chain, applying multiple encoding and decoding steps to effectively manipulate the file's content before accessing it.

![](<https://miro.medium.com/v2/resize:fit:828/format:webp/1*FcZJtmdheIsom9n8ahWUlw.png>)

To execute the payload, I used curl to send a POST request. Here's the command I ran:  
```  
curl -X POST -d "file=php://filter/.../resource=/flag.txt"   
<http://ad2c166b480ae8b190c81.playat.flagyard.com> > Freeflag.txt  
```  
and got the flag.

![](<https://miro.medium.com/v2/resize:fit:828/format:webp/1*nxkSZVT-mtqGBVcIxh_McA.png>)

Pwned!!

![](<https://miro.medium.com/v2/resize:fit:828/format:webp/1*Ftfqbk09YVwdUWagxGEWDQ.png>)
