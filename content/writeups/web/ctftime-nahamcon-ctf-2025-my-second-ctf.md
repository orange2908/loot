---
title: "My Second CTF - NahamCon CTF 2025"
category: "web"
subcategory: "fuzzing"
type: "writeup"
tags: ["web", "fuzzing", "wordlists", "second", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "I guessed this challenge is similar to part 1 (ROT1) but we have a specific wordlist to use."
source:
  name: "CTFtime writeup #40299"
  url: "https://ctftime.org/writeup/40299"
original_source: "https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_second_ctf/"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "My Second CTF"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** My Second CTF
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/40299>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_second_ctf/>

---
I guessed this challenge is similar to part 1 (ROT1) but we have a specific wordlist to use.

![](<https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_second_ctf/images/rotten-app-initial-page.png>)

It says "one more step rotten", so I think we might need to ROT2 the wordlist. First, I'll just try ROT1. I give the wordlist to ChatGPT and let it do the work for me ?

![](<https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_second_ctf/images/rot1-wordlist-results.png>)

We get nothing, so let's try ROT2.

![](<https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_second_ctf/images/rot2-wordlist-discovery.png>)

We find the correct endpoint! However, if we follow the redirection, we are missing a parameter.

![](<https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_second_ctf/images/missing-parameter-redirect.png>)

We'll repeat the process, this time fuzzing GET params with our rotated wordlist. Note, we need to set burp intruder to follow redirections, or they will all show 301.

![](<https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_second_ctf/images/burp-intruder-parameter-fuzzing.png>)

We quickly obtain the flag!

Flag: `flag{9078bae810c524673a331aeb58fb0ebc}`
