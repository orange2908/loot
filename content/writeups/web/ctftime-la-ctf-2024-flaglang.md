---
title: "flaglang - LA CTF 2024"
category: "web"
type: "writeup"
tags: ["web", "flaglang", "la-ctf", "la-ctf-2024", "2024", "ctf-writeup"]
summary: "Looking at Flaglang it is a plain website where we can select countries and see 'Hello world' in various languages, at the very top is an interesting option, Flagistan."
source:
  name: "CTFtime writeup #39098"
  url: "https://ctftime.org/writeup/39098"
original_source: "https://seall.dev/posts/lactf2024#webflaglang-606-solves"
ctf:
  name: "LA CTF 2024"
  year: 2024
  challenge: "flaglang"
---

## Metadata

- **CTF:** LA CTF 2024
- **Task:** flaglang
- **Author team:** IrisSec
- **CTFtime:** <https://ctftime.org/writeup/39098>
- **Original writeup:** <https://seall.dev/posts/lactf2024#webflaglang-606-solves>

---
# web/flaglang (606 solves)  
> Do you speak the language of the flags?

Looking at Flaglang it is a plain website where we can select countries and see 'Hello world' in various languages, at the very top is an interesting option, Flagistan.

![flaglang-1.png](https://seall.dev/images/ctfs/lactf2024/flaglang-1.png)

Looking at the source code provided we can see that the countries are stored in YAML and the country 'Flagistan' seems to deny all country codes.

Scrolling through the YAML I notice that 'NO' for Norway is highlighted blue.

![flaglang-2.png](https://seall.dev/images/ctfs/lactf2024/flaglang-2.png)

YAML seems to parse YES/NO as objects like true/false rather than strings, so we can cause the server to load an invalid object (which isn't on Flagistans deny list), allowing us to render the flag!

![flaglang-3.png](https://seall.dev/images/ctfs/lactf2024/flaglang-3.png)

Bam! We can see the flag!

Flag: `lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}`
