---
title: "iDoor - NahamCon CTF 2024"
category: "web"
subcategory: "idor"
type: "writeup"
tags: ["web", "idor", "idoor", "nahamcon-ctf", "nahamcon-ctf-2024", "2024", "ctf-writeup"]
summary: "Simple IDOR (Insecure direct object references), where camera ID encoded to sha256 hash"
source:
  name: "CTFtime writeup #39161"
  url: "https://ctftime.org/writeup/39161"
original_source: "https://github.com/zer00d4y/writeups/blob/main/CTF%20events/NahamCon%20CTF/NahamCon%20CTF%202024.md"
ctf:
  name: "NahamCon CTF 2024"
  year: 2024
  challenge: "iDoor"
---

## Metadata

- **CTF:** NahamCon CTF 2024
- **Task:** iDoor
- **Author team:** RedNet
- **CTFtime:** <https://ctftime.org/writeup/39161>
- **Original writeup:** <https://github.com/zer00d4y/writeups/blob/main/CTF%20events/NahamCon%20CTF/NahamCon%20CTF%202024.md>

---
Simple IDOR (Insecure direct object references), where camera ID encoded to sha256 hash 

![image](<https://github.com/zer00d4y/writeups/assets/128820441/ec62cf43-5e26-482b-b84d-a77092dab7f2>)

4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8 -> 11

![image](<https://github.com/zer00d4y/writeups/assets/128820441/860cd3de-47b4-4341-ba54-fb1c370228f9>)

![image](<https://github.com/zer00d4y/writeups/assets/128820441/f3056d87-eabb-4375-8a47-adaab98d70c9>)

0 -> 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9

![image](<https://github.com/zer00d4y/writeups/assets/128820441/366374fb-2998-4c39-8abf-424d4e605d0c>)

FLAG:

flag{770a058a80a9bca0a87c3e2ebe1ee9b2}
