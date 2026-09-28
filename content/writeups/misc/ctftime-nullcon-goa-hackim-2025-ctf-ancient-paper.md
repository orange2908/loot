---
title: "Ancient paper - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "ancient", "paper", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "\\- We are given an image file along the following description: “I found this ancient artifact stuck in an old machine labeled “29”."
source:
  name: "CTFtime writeup #39998"
  url: "https://ctftime.org/writeup/39998"
original_source: "https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Ancient paper"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Ancient paper
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39998>
- **Original writeup:** <https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/>

---
# ancient paper

## Description  
\- We are given an image file along the following description: “I found this ancient artifact stuck in an old machine labeled “29”. But what is its purpose?”

## Solution

\- Initial inspection leads to the conclusion that the image is of an IBM-29 punch card which was carrying our flag as its data.

## Decoding the flag  
\- Then I used the following mapping of the IBM-29 punch card to decode the data.  
![digit_table](<https://w1r3w01f.github.io/images/digit_mapping.png>)  
![alpha_table](<https://w1r3w01f.github.io/images/alpha_mapping.png>)

\- Which lead to the following text:  
```  
1337 FORMAT ENO H0LL3R1TH 3NC0D3D F0RTR4N PRINT 1337  
```  
\- And hence we get our flag as:

## Flag  
`ENO{H0LL3R1TH_3NC0D3D_F0RTR4N}`
