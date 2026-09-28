---
title: "life - de1ctf 2020"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "qr-code", "life", "disk", "forensic"]
summary: "Binwalk the file, we get two files: some dot image called passphare.png and a"
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/de1ctf-2020/life/README.md"
ctf:
  name: "de1ctf"
  year: 2020
  challenge: "life"
---

## Source

- **CTF:** de1ctf 2020
- **Challenge:** life
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/de1ctf-2020/life/README.md>

---
# Life

Binwalk the file, we get two files: some dot image called passphare.png and a
flag.zip file encrypted with a password. 

Now let's look back to the description of the problem: "No Game, No Life!" Hmm
sounds like game of life! Now if we plug in into game of life and step one
forward we get this:

![The QR code][1]

Then we get password: AJTC8ADEVRA13AR from QR code. Unzip and get the flag, QED.

[1]: life.png
