---
title: "Strange-Historical-Machine - SpringForwardCTF"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "exiftool", "cyberchef", "strange-historical-machine", "disk", "springforwardctf", "ctf-writeup"]
summary: "Used exiftool on the file and the Comment section had a link-MuseoscienzaetecnologiaMilano.jpg)>."
source:
  name: "CTFtime writeup #39131"
  url: "https://ctftime.org/writeup/39131"
ctf:
  name: "SpringForwardCTF"
  challenge: "Strange-Historical-Machine"
---

## Metadata

- **CTF:** SpringForwardCTF
- **Task:** Strange-Historical-Machine
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39131>

---
Used exiftool on the file and the Comment section had a [link](<https://commons.wikimedia.org/wiki/File:Enigma_(crittografia)_-_Museo_scienza_e_tecnologia_Milano.jpg)>.

I noticed that the file has some data so i extracted them using Binwalk and found a text.txt file.

I put it on Cyberchef and got the flag.

![photo](<https://github.com/juke-33/Write-ups/raw/main/SpringForwardCTF2024/Misc/Strange-Historical-Machine/Photo1.png>)

Flag: `nicc{Y0U_KN0W_3N1GMA_C0D3}`
