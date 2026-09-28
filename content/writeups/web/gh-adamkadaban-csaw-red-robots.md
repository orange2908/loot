---
title: "robots - CSAW Red 2020"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "robots", "web-exploitation", "csaw-red", "adamkadaban", "ctfs"]
summary: "web writeup for \"robots\" from CSAW Red - techniques: robots, web-exploitation, csaw-red, adamkadaban, ctfs."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/web/robots/README.md"
ctf:
  name: "CSAW Red"
  year: 2020
  challenge: "robots"
---

## Source

- **CTF:** CSAW Red 2020
- **Challenge:** robots
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/web/robots/README.md>

---
> Only robots can find my treasure
[http://web.red.csaw.io:5000](http://web.red.csaw.io:5000/)

1. The web challenge is called "robots", so we can assume that we need to look at `robots.txt`
    - Go to http://web.red.csaw.io:5000/robots.txt
2. Here, we find a list of directories
    - One of them is called `/super-duper-extra-secret-very-interesting`
3. Go to http://web.red.csaw.io:5000/super-duper-extra-secret-very-interesting
4. The flag is flag{welcome_to_website_hacking}
