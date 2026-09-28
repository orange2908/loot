---
title: "Minerva's-Quest - SpringForwardCTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "minerva", "s-quest", "springforwardctf", "ctf-writeup"]
summary: "Unfortunately this CTF site is down (unavailable) at this moment, so I can not show you a challenge description, but in general there was a link to Google Forms."
source:
  name: "CTFtime writeup #39351"
  url: "https://ctftime.org/writeup/39351"
original_source: "https://medium.com/@embossdotar/ctf-writeup-springforwardctf-minervas-quest-869b3e5907fc"
ctf:
  name: "SpringForwardCTF"
  challenge: "Minerva's-Quest"
---

## Metadata

- **CTF:** SpringForwardCTF
- **Task:** Minerva's-Quest
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39351>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-springforwardctf-minervas-quest-869b3e5907fc>

---
Hi All,

Unfortunately this CTF site is down (unavailable) at this moment, so I can not show you a challenge description, but in general there was a link to [Google Forms](<https://www.google.com/forms/about/>).

As you know, the link starts with <https://docs.google.com/forms/> so it is external page of course.

The view of this form looks like below:

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*n4wrKuANx_NfF0WexePcRg.png>)

Google Form view, source: SpringForwardCTF 2024

I guess you wouldn’t want to log in to your Google account there :P  
Moreover, we can see there about 13 pages and some weird values.  
What is going on? Is it some kind of encoding or [cipher](<https://www.dcode.fr/)?> Should we combine these values and check different possibilities?

Before that, I prefer to check a site deeper. So let’s do it!  
CTRL+U and now CTRL+F (search for) -> “NICC{“

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*8HXaYoR3n4e6dRvKCe-RIw.png>)

Flag view, source: SpringForwardCTF 2024

Flag: **NICC{_Minerva’s_Blessing_for_U}**

**Short summary:** that was easy task, but it’s not the case — here we had to examinate our future approach. We could try to fill this form (by clicking I suppose), or checking in terms of possible encoding or cipher, but it was better for us **to make a simple manual recon at first**.

I hope you enjoy!
