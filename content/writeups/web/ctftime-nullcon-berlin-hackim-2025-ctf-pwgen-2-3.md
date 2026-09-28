---
title: "pwgen - Nullcon Berlin HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "pwgen", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The page shows you the 130 character long flag, but shuffled between 1 and 1000 times (chosen via a URL parameter)."
source:
  name: "CTFtime writeup #40399"
  url: "https://ctftime.org/writeup/40399"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "pwgen"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** pwgen
- **Author team:** taylor8294
- **CTFtime:** <https://ctftime.org/writeup/40399>

---
The page shows you the 130 character long flag, but shuffled between 1 and 1000 times (chosen via a URL parameter).

The source indicates the shuffles are all done with a fixed seed of `0x1337` passed to `srand` before the first shuffle is done.

I used the same seed to shuffle once a string of 130 unique bytes. I created a map of where each byte was shuffled to. I then used that map to unshuffle the flag shown on the shuffled once page.

Here is my solve script.

```php
