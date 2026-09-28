---
title: "Sherlock - Texas Security Awareness Week 2024"
category: "osint"
subcategory: "classical"
type: "writeup"
tags: ["osint", "vigenere", "sherlock", "classical", "texas-security-awareness-week", "texas-security-awareness-week-2024", "2024", "ctf-writeup"]
summary: "I need to study for a class but the quizlet I'm using has jumbled up answers that just don't make sense."
source:
  name: "CTFtime writeup #38958"
  url: "https://ctftime.org/writeup/38958"
original_source: "https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/osint/sherlock.html"
ctf:
  name: "Texas Security Awareness Week 2024"
  year: 2024
  challenge: "Sherlock"
---

## Metadata

- **CTF:** Texas Security Awareness Week 2024
- **Task:** Sherlock
- **Author team:** reCAPTCHA the Flag
- **CTFtime tags:** osint, vigenere
- **CTFtime:** <https://ctftime.org/writeup/38958>
- **Original writeup:** <https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/osint/sherlock.html>

---
I need to study for a class but the quizlet I'm using has jumbled up answers that just don't make sense. Can you figure out how to read it?

[<https://quizlet.com/882185739/sherlock-flash-cards/?funnelUUID=acf2df22-5f5c-4a67-9131-d0b6b18047df>](<https://quizlet.com/882185739/sherlock-flash-cards/?funnelUUID=acf2df22-5f5c-4a67-9131-d0b6b18047df>) 

\---

Visit the Quizlet. In the description, it includes a link to a twitter user [here](<https://twitter.com/texsaw24>). There, they post something about using the Vigenere cipher with the key HACK. 

Looking through the quizlet terms, we find some brackets at cards 10 and 11. Probably where the flag is! We can copy the text in cards 10 and 11 and just add some letters at the front, testing all possible offsets (0-3) until we get the flag! Note that you can use [this site](<https://www.dcode.fr/vigenere-cipher>) to decrypt. 

texsaw{vig3n3r3_x!pher}
