---
title: "LetMeIn - Insomni'hack 2024"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "letmein", "insomni-hack", "insomni-hack-2024", "2024", "ctf-writeup"]
summary: "from memory and a partial note."
source:
  name: "CTFtime writeup #39149"
  url: "https://ctftime.org/writeup/39149"
ctf:
  name: "Insomni'hack 2024"
  year: 2024
  challenge: "LetMeIn"
---

## Metadata

- **CTF:** Insomni'hack 2024
- **Task:** LetMeIn
- **Author team:** BOT-Bern
- **CTFtime:** <https://ctftime.org/writeup/39149>

---
from memory and a partial note.

The web page contained a SQL injection.

There was a condition to pass in order to go into the get results.

if username != 'admin' or password[:5] != 'admin' or password[-5:] != 'admin':  
...exit()  
  
This required username to be "admin"  
And it required that the password starts with admin [:5] and finished with admin [-5:]

The classic SQL injection = " klklk' OR '1=1' " will not work and needed to be transformed into "admin' OR '(something TRUE finishing with admin')"  
So the final result was  
username="admin"  
password="admin'+OR+'admin=admin'"
