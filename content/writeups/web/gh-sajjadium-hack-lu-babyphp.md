---
title: "babyphp - Hack lu 2018"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "babyphp", "web-exploitation", "hack-lu", "sajjadium", "ctf-writeups"]
summary: "In Hack.lu 2018 - BabyPHP challenge, there is an unsanitized user input vulnerability which results in unintended behaviors as well as code injection."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/Hack.lu/2018/babyphp/README.md"
ctf:
  name: "Hack lu"
  year: 2018
  challenge: "babyphp"
---

## Source

- **CTF:** Hack lu 2018
- **Challenge:** babyphp
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/Hack.lu/2018/babyphp/README.md>

---
In `Hack.lu 2018 - BabyPHP` challenge, there is an `unsanitized user input` vulnerability which results in `unintended behaviors` as well as `code injection`. First, we can provide a `data:` URL to `file_get_contents` to return the required value. Then, we should pass `Array` in the parameter, so we force `substr` and `sha1` return `null`. Also, we can override the values of arbitrary variables using `$$` in `PHP`. Finally, we can run arbitrary code by passing arbitrary `$bb` value into `assert` in order to print `$flag`. This is an interesting `web` challenge to learn how to attack `PHP` applications.
