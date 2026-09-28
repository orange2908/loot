---
title: "An Unlikely Partnership - UIUCTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "unlikely", "partnership", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "As a kind of 'handle' you have long and short name: Long Island Subway Authority (LISA) - the target."
source:
  name: "CTFtime writeup #39290"
  url: "https://ctftime.org/writeup/39290"
original_source: "https://medium.com/@embossdotar/ctf-writeup-uiuctf-2024-an-unlikely-partnership-c1233105bdbb"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "An Unlikely Partnership"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** An Unlikely Partnership
- **Author team:** ctfrrteam
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/39290>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-uiuctf-2024-an-unlikely-partnership-c1233105bdbb>

---
Hi All.   
As a kind of 'handle' you have long and short name: Long Island Subway Authority (LISA) - the target. From task's description you can notice "(...) strategic business partnership" - keypoint. It suggests LinkedIn as a social media platform focused at similar topics.

To be truly, it is hidden in "deep web". If you don't have account there, you will have little harder job. In general, some info are public, but it is better to check this as logged-in user, because then you will have more features. (get a flag in shortest time)  
You can use tiny dorking like here: site:[linkedin.com](http://linkedin.com) "Long Island Subway Authority" - it exist.

Depends on your approach you can check at start posts, interests, activity and so on.   
Winning steps were to check Skills section. You can notice there "Endorsements" by someone. Who's that?  
It is "UIUC Chan". Let's take a look at the profile! That's it.

Flag - solution:  
uiuctf{0M160D_U1UCCH4N_15_MY_F4V0r173_129301}

I hope you enjoy!
