---
title: "The Gang 2 - n00bzCTF 2024"
category: "stego"
type: "writeup"
tags: ["stego", "gang", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "Hi All, Challenge description is like below:"
source:
  name: "CTFtime writeup #39380"
  url: "https://ctftime.org/writeup/39380"
original_source: "https://medium.com/@embossdotar/ctf-writeup-n00bzctf-2024-the-gang-2-10ddfddb086f"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "The Gang 2"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** The Gang 2
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39380>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-n00bzctf-2024-the-gang-2-10ddfddb086f>

---
Hi All, Challenge description is like below:

"You may have gotten your first flag, but it’s just the beginning! John Doe, as overconfident as he is, has left you with a riddle. Maybe it hides some secrets? Continue where you left off last time. Flag will already by wrapped in n00bz{} Author: NoobMaster"

Challenge does not contain any file. That’s all at this moment from the content.

It is from [OSINT](<https://en.wikipedia.org/wiki/Open-source_intelligence>) category.

It is also the second part of ‘The Gang’ challenge — so it would be good, if you have resolved the first one. This task has a little more than 200 solves, while the previous part of it has almost 600 solves, so approximate proportion is a “1:3”, interesting.

I wanted to write about this, because I liked very much some part of this.

STEGANO:D But please wait a second, not all at once.

As I am enthusiast of educational kind of writeups in general, short explanation — stegano is a short from [steganography](<https://en.wikipedia.org/wiki/Steganography):>

"Technique of hiding data within an ordinary, nonsecret file or message to avoid detection; source: <https://www.techtarget.com/searchsecurity/definition/steganography> "

“Continue where you left off last time” — nice hint. In short, with previous part you could find a link to JohnDoe’s article.

It looks like a kind of poem, you can see it below:

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*pBtOBqKVwAFA_0Bis6GY-A.png>)

JohnDoe’s article — Blog, source: n00bzCTF 2024 — https://n00bzunit3d.xyz/blog/who-am-i/

Quick note — if you want to solve it yourself, give yourself some time now — later it will be too late, because you will already see the solution; that means no such fun:P

Written form for convenient of automated translations:

"Who Am I?

JohnDoe

Underneath the surface, secrets lie.

Stories untold, hidden from the eye.

Every question leads to more unknown.

Real mysteries, only few are shown.

Never revealing, always concealed.

A hidden truth, never revealed.

Many have searched, but none have found.

Every clue, like whispers, sound.

In the shadows, I silently stand.

Secrets I keep, like grains of sand.

Just a glimpse, you might get to see.

Only hints, no certainty.

Hidden pathways, a cryptic code.

Navigating through the winding road.

Have you the wit to break this scheme?

Answers lie beyond the dream.

Codes and puzzles, all intertwined.

Knowledge and wisdom, together aligned.

Every detail, a piece to decode.

Remember, persistence will lighten the load.

Do you have what it takes to unveil?

Only the cleverest will prevail.

Enter the realm of the unknown.

ChatGPT LOL "

source: n00bzCTF 2024 — https://n00bzunit3d.xyz/blog/who-am-i/ 

To be truly, I am interested about your approach at this step!

Is it time for short manual recon, enumeration (robots.txt, sitemap.xml or other)? Is it time for OSINT with copy — paste the text and searching other hints? Some occurrences in the [surface web](<https://en.wikipedia.org/wiki/Surface_web)?> What about [deep-web](<https://en.wikipedia.org/wiki/Deep_web)?>

Nah. Spoiler alert! “Read between the lines”.

Look at this again:

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*EcQUwHmJcO6Vgtu_w6n17w.png>)

Hidden message (stegano part), source: n00bzCTF 2024

We can see the hidden message:   
“USERNAME IS JOHN HACKER DOE”

But, now what? The first hint was “Continue where you left off last time”. That was about a first step.

We got to know the hidden message — but why? Is it just a wordplay, a fun? Or maybe, is it a kind of another hint?

Will you be focused on the previous site, blog to search for this possible user? You can. You can also use [OSINT framework](<https://osintframework.com/>) with many tools. In my case tools failed a little bit, because for solution (very soon will be disclosed here) shows something like ‘Unknown’ (no access for proper endpoint or similar).

I decided to check this in manual way — Twitter (currently known as ‘[X.com](http://X.com)’).

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*yCEZNaILQrRZJzeUgoWZXA.png>)

Flag, source: Twitter/[X.com](http://X.com) site & n00bzCTF 2024

Flag: **n00bz{5t0p_ch4s1ng_m3_4f2d1a7d}**

Cool [ASCII art](<https://en.wikipedia.org/wiki/ASCII_art>).  
By the way, it was hidden in the deep web, because currently Twitter requires to be a logged in there (redirection <https://x.com/i/flow/login?redirect_after_login=>).

I hope you enjoy!
