---
title: "Way 2-Basic - NahamCon-EU-CTF 2022"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "cyberchef", "way", "basic", "miscellaneous", "way-2-basic"]
difficulty: "easy"
summary: "misc writeup for \"Way 2-Basic\" from NahamCon-EU-CTF - techniques: cyberchef, way, basic, miscellaneous, way-2-basic."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Way-2-Basic/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Way-2-Basic/README.md"
ctf:
  name: "NahamCon-EU-CTF"
  year: 2022
  challenge: "Way 2-Basic"
---

## Source

- **CTF:** NahamCon-EU-CTF 2022
- **Challenge:** Way 2-Basic
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Way-2-Basic/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Way-2-Basic/README.md>

---
# Way 2 Basic

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: Easy

## Background

Author: @JohnHammond#6971  
  
Here is some data represented in [base 2](https://en.wikipedia.org/wiki/Binary_number). What is this data represented as [ASCII](https://en.wikipedia.org/wiki/ASCII) text?  
  
`01100110 01101100 01100001 01100111 01111011 00111001 00110000 01100011 00110110 01100101 01100010 01100101 00111001 00110100 00110001 00110101 00110110 00110001 01100011 01100110 01100001 01100100 01100110 01100001 01100101 00110001 00110111 00110000 01100001 00111000 01100110 00110000 01100101 01100001 00110010 00110101 00110010 01111101`

## Find The Flag

**In here, we can throw those base 2(binary) data to [CyberChef](https://gchq.github.io/CyberChef/)!**

> Note: Binary is just `1`s and `0`s, as the name suggested, base 2.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216222257.png)

Found it!

- **Flag: `flag{90c6ebe941561cfadfae170a8f0ea252}`**

# Conclusion

What we've learned:

1. Converting binary data to ASCII text
