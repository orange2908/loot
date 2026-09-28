---
title: "Banjo - NahamCon-EU-CTF 2022"
category: "misc"
subcategory: "image"
type: "writeup"
tags: ["misc", "jpeg", "regex", "banjo", "image", "miscellaneous"]
difficulty: "easy"
summary: "misc writeup for \"Banjo\" from NahamCon-EU-CTF - techniques: jpeg, regex, banjo, image, miscellaneous."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Banjo/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Banjo/README.md"
ctf:
  name: "NahamCon-EU-CTF"
  year: 2022
  challenge: "Banjo"
---

## Source

- **CTF:** NahamCon-EU-CTF 2022
- **Challenge:** Banjo
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Banjo/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Banjo/README.md>

---
# Banjo

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: Easy

## Background

Author: @JohnHammond#6971  

Oooh, that classic twang! The banjo is one of my favorite [`strings`](https://en.wikipedia.org/wiki/Strings_(Unix)) instruments!  

**Download the file below.**

**Attachments:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/Banjo]
└─# file banjo.jpg 
banjo.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, progressive, precision 8, 366x400, components 3
```

## Find The Flag

**As the challenge's background suggested, we need to use Linux command `strings`!**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/Banjo]
└─# strings banjo.jpg | grep -oE 'flag{.*?}'
flag{ce4e687e575392ae242f0e41c888de11}
```

> Note: In here, I used `strings` command, then I piped (`|`) it, or I let the output of the `strings` command to the next command, which is `grep`. And `grep` `-o` flag is to find only match result, then `-E` flag is to use regular expression(regex) to find the flag.

Found it!

- **Flag: `flag{ce4e687e575392ae242f0e41c888de11}`**

# Conclusion

What we've learned:

1. Linux List Strings via `strings`
