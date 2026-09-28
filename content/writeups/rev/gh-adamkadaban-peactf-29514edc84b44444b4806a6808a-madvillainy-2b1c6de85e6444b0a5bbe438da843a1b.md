---
title: "MadVillainy 2b1c6de85e6444b0a5bbe438da843a1b - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "madvillainy", "b1c6de85e6444b0a5bbe438da843a1b", "reverse-engineering", "madvillainy-2b1c6de85e6444b0a5bbe438da84", "peactf-29514edc84b44444b4806a6808a"]
summary: "The flag starts with \"Mr.\" and is case-insensitive."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/MadVillainy%202b1c6de85e6444b0a5bbe438da843a1b.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "MadVillainy 2b1c6de85e6444b0a5bbe438da843a1b"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** MadVillainy 2b1c6de85e6444b0a5bbe438da843a1b
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/MadVillainy%202b1c6de85e6444b0a5bbe438da843a1b.md>

---
# MadVillainy

> An evil villain dubbed the “Triplet Lock” has recently been going around and messing with everyone’s audio files! A detective managed to find out his true identity but Triplet Lock was able to encrypt it before he was caught, can you find out what his true name is?
The flag starts with "Mr." and is case-insensitive.

1. This challenge took me a bit to figure out... its not very intuitive
2. After some trial and error, I realized I could reverse the audio and get something that sounded like it started with "Mr."
    - [https://audiotrimmer.com/online-mp3-reverser/](https://audiotrimmer.com/online-mp3-reverser/)
3. However, it was still to fast and deep to understand
    - I used this site to edit the pitch and speed
        - [https://29a.ch/timestretch/](https://29a.ch/timestretch/)
    - .8 speed and 9 semitones sounded good
4. Sounds like Mr. Heartwall? That didn't work though... so I looked up "encryption" along with "Heartwall" in the hopes that the names had to relate. Looks like Hartwell was the name
5. The flag is Mr.Hartwell
