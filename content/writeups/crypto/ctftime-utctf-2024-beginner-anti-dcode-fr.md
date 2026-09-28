---
title: "Beginner: Anti-dcode.fr - UTCTF 2024"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "cyberchef", "beginner", "anti-dcode", "classical", "utctf", "utctf-2024", "2024", "ctf-writeup"]
summary: "Working with the file I do the following."
source:
  name: "CTFtime writeup #39087"
  url: "https://ctftime.org/writeup/39087"
original_source: "https://seall.dev/posts/utctf2024#beginner-anti-dcodefr"
ctf:
  name: "UTCTF 2024"
  year: 2024
  challenge: "Beginner: Anti-dcode.fr"
---

## Metadata

- **CTF:** UTCTF 2024
- **Task:** Beginner: Anti-dcode.fr
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39087>
- **Original writeup:** <https://seall.dev/posts/utctf2024#beginner-anti-dcodefr>

---
# Beginner: [Anti-dcode.fr](http://Anti-dcode.fr)   
> I've heard that everyone just uses [dcode.fr](http://dcode.fr) to solve all of their crypto problems. Shameful, really. This is really just a basic Caesar cipher, with a few extra random characters on either side of the flag. Dcode can handle that, right? >:) The '{', '}', and '_' characters aren't part of the Caesar cipher, just a-z. As a reminder, all flags start with "utflag{".

Working with the file I do the following. I put the file into [CyberChef](<https://gchq.github.io/CyberChef/>), and do a `ROT13` and then a `Find / Replace` and check for any instances of the string `utflag{`.

I roll through the rotation till I see a length drop in the output at `18`.

I delete the `Find / Replace`, and save the output.

Searching the saved output for `utflag{` I find the flag.

Flag: `utflag{rip_dcode}`
