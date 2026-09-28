---
title: "grandmas_notes - Nullcon Berlin HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "grandmas", "notes", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "I tried \"test\" as username and \"test\" as password and got a message like user not found."
source:
  name: "CTFtime writeup #40398"
  url: "https://ctftime.org/writeup/40398"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "grandmas_notes"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** grandmas_notes
- **Author team:** taylor8294
- **CTFtime:** <https://ctftime.org/writeup/40398>

---
I tried "test" as username and "test" as password and got a message like user not found.

I tried "admin" as username and "admin" as password and the site tells you how many characters you got right in the password so far. For example, if the password was "HorseStaple" and you tried "Home" it would say 2 characters are correct. So you can just brute force the first letter of admin's password until it says 1 character right, then brute force the second and so on until the password works.

Once you are logged in, the flag is just in the users "notes" in the application.

Here is my solve script.

```js  
let alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"£$%^&*()-=[]#;\',./_+{}~:@<>?|'.split('');  
let pass = '';  
while(pass.length < 64){  
let exhausted = true;  
for(let i=0; i
