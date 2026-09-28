---
title: "WOLPHV I: Reconnaissance - WolvCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "base64", "wolphv", "reconnaissance", "wolvctf", "wolvctf-2024", "2024", "ctf-writeup"]
summary: "A new ransomware group you may have heard about has emerged: WOLPHV"
source:
  name: "CTFtime writeup #38951"
  url: "https://ctftime.org/writeup/38951"
original_source: "https://nightxade.github.io/ctf-writeups/writeups/2024/Wolv-CTF-2024/osint/wolphv-i-reconaissance.html"
ctf:
  name: "WolvCTF 2024"
  year: 2024
  challenge: "WOLPHV I: Reconnaissance"
---

## Metadata

- **CTF:** WolvCTF 2024
- **Task:** WOLPHV I: Reconnaissance
- **Author team:** Nightxade
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/38951>
- **Original writeup:** <https://nightxade.github.io/ctf-writeups/writeups/2024/Wolv-CTF-2024/osint/wolphv-i-reconaissance.html>

---
A new ransomware group you may have heard about has emerged: WOLPHV

There's already been reports of their presence in articles and posts.

NOTE: Wolphv's twitter/X account and <https://wolphv.chal.wolvsec.org/> are out of scope for all these challenges. Any flags found from these are not a part of these challenges

This is a start to a 5 part series of challenges. Solving this challenge will unlock WOLPHV II: Infiltrate

\---

Searching up `wolphv`, we can find a tweet about them [here](<https://twitter.com/FalconFeedsio/status/1706989111414849989>). Scrolling down, we find a reply from user @JoeOsint__ 

```  
woah!!! we need to investigate this  
d2N0Znswa18xX2QwblRfdGgxTmtfQTFfdzFsbF9yM1BsNGMzX1VzX2YwUl80X2wwbmdfdDFtZX0=  
```

Base64 decoding this online reveals the flag! 

wctf{0k_1_d0nT_th1Nk_A1_w1ll_r3Pl4c3_Us_f0R_4_l0ng_t1me}
