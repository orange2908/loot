---
title: "WOLPHV I: Reconnaissance - WolvCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "base64", "wolphv", "reconnaissance", "wolvctf", "wolvctf-2024", "2024", "ctf-writeup"]
summary: "\\- Description: A new ransomware group you may have heard about has emerged: WOLPHV."
source:
  name: "CTFtime writeup #38970"
  url: "https://ctftime.org/writeup/38970"
original_source: "https://github.com/archv1le/CTF-Write-Ups/blob/main/WolvCTF%202024/WOLPHV%20I%3A%20Reconnaissance/Solution.md"
ctf:
  name: "WolvCTF 2024"
  year: 2024
  challenge: "WOLPHV I: Reconnaissance"
---

## Metadata

- **CTF:** WolvCTF 2024
- **Task:** WOLPHV I: Reconnaissance
- **Author team:** r1p3rS
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/38970>
- **Original writeup:** <https://github.com/archv1le/CTF-Write-Ups/blob/main/WolvCTF%202024/WOLPHV%20I%3A%20Reconnaissance/Solution.md>

---
## WOLPHV I: Reconnaissance  
\- Tags: OSINT  
\- Description: A new ransomware group you may have heard about has emerged: WOLPHV. There's already been reports of their presence in articles and posts. NOTE: Wolphv's twitter/X account and <https://wolphv.chal.wolvsec.org/> are out of scope for all these challenges. Any flags found from these are not a part of these challenges. This is a start to a 5 part series of challenges. Solving this challenge will unlock WOLPHV II: Infiltrate.

## Solution  
\- Use Google to find the tweet about this. The query for the search is "wolphv". <https://twitter.com/FalconFeedsio/status/1706989111414849989> (tweet)  
\- Scrolling down, we find a reply from user @JoeOsint__

```  
woah!!! we need to investigate this  
d2N0Znswa18xX2QwblRfdGgxTmtfQTFfdzFsbF9yM1BsNGMzX1VzX2YwUl80X2wwbmdfdDFtZX0=  
```

\- This is a Base64 string, after decoding it, we get:

```  
wctf{0k_1_d0nT_th1Nk_A1_w1ll_r3Pl4c3_Us_f0R_4_l0ng_t1me}  
```
