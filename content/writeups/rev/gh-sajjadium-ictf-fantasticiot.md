---
title: "fantasticiot - iCTF 2018"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "objdump", "fantasticiot", "static-analysis", "reverse-engineering", "ictf"]
summary: "There vulnerability is in the getflag, there is a strncmp."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/iCTF/2018/fantasticiot/README.md"
ctf:
  name: "iCTF"
  year: 2018
  challenge: "fantasticiot"
---

## Source

- **CTF:** iCTF 2018
- **Challenge:** fantasticiot
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/iCTF/2018/fantasticiot/README.md>

---
There vulnerability is in the `get_flag`, there is a `strncmp`. Basically, if you provide empty string as one of the parameters, it will return `0` because the `n` parameter is extracted from the provided `token`.

In order to fix it, you just need to replace `strncmp` with `strcmp`. The following line is from objdump. You need to replace `8048c95` with `8113480`:

`80497ae:       e8 e2 f4 ff ff          call   8048c95 <strncmp>`
