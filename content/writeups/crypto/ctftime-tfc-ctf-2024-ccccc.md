---
title: "CCCCC - TFC CTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "cyberchef", "ccccc", "tfc-ctf", "tfc-ctf-2024", "2024", "ctf-writeup"]
summary: "Hi All, Challenge description is like below:"
source:
  name: "CTFtime writeup #39381"
  url: "https://ctftime.org/writeup/39381"
original_source: "https://medium.com/@embossdotar/ctf-writeup-tfc-ctf-2024-ccccc-a0cd075518de"
ctf:
  name: "TFC CTF 2024"
  year: 2024
  challenge: "CCCCC"
---

## Metadata

- **CTF:** TFC CTF 2024
- **Task:** CCCCC
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39381>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-tfc-ctf-2024-ccccc-a0cd075518de>

---
Hi All, Challenge description is like below:

"   
Title: CCCCC

CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC

CCCCC CCCCC CCCCC

Author: hofill "

Challenge contains a file — ccccc.txt

" Content of the ccccc.txt file:

5c4c4c6c4c3c4c3c5c4c4c6c7cbc6c3c7c3c6c8c6cfc7c5c7c4c5cfc6c3c6cfc7c5c7c4c5cfc6c3c7c4c3c0c5cfc6c3c6cdc7c9c5cfc6c3c6c2c3c0c7c9c5cfc6c3c3c4c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c4c6cfc6c7c5cfc6c3c6c1c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c3c3c4c3c7c7cdc0ca "

That’s all. What are you doing now? What are the steps?  
Category: [Crypto](<https://en.wikipedia.org/wiki/Cryptography>).

Quick note — if you want to solve it yourself, give yourself some time now — later it will be too late, because you will already see the solution; that means no such fun:P

I wanted to write about this, because I have a pretty nice tip for you: if you’re tired, get a rest for a while:D I will explain it little bit later.

Look, what do you associate ‘C’ with and the number/s? For example ‘X’ in [Roman numerals](<https://en.wikipedia.org/wiki/Roman_numerals>) means ‘10’. ‘C’ means ‘100’, etc. Is it useful? Maybe. Or maybe not. How can we know at start here?

It don’t have to be in Roman numerals.

Any patterns?

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*s3ZOfdMMmXmDuhWOhE4oKg.png>)

Initial analysis, source: TFC CTF 2024

Looks like that file named ‘ccccc.txt’ is just a long string.

Referring to my previous ‘[lifehack](<https://en.wikipedia.org/wiki/Life_hack)’> — I solved harder challenges there (I focused on this a bit later), and I was a little bit confused at that moment.

In this case [CyberChef](<https://gchq.github.io/CyberChef/>) (‘Magic’ and so on) failed, [dCode](<https://www.dcode.fr/>) also. Many other approaches — too. No result.

But… I decided to take a short break, making some completely different activities — and… I came back with some idea!

Great idea!

What if it can be easier as you think? Don’t overthink at this case!

I decided to paste this ‘long string’ in one of my fav code’s editor and remove (cut out) all these ‘C’ letters.

Result:

5446434354467b6373686f75745f636f75745f6374305f636d795f636230795f63346e645f636d795f63646f675f63616e645f636d795f636334377d0a

There was definitely too much ‘C’. Now, looks better. I bet, you know the next steps.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*UrztOMctl-XejXosmeb9EQ.png>)

Flag — solution, source: CyberChef & TFC CTF 2024

Flag: **TFCCTF{cshout_cout_ct0_cmy_cb0y_c4nd_cmy_cdog_cand_cmy_cc47}**

I hope you enjoy!
