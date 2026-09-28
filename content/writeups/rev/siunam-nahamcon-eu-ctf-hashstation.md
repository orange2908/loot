---
title: "Hashstation - NahamCon-EU-CTF 2022"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "hashstation", "reverse-engineering", "nahamcon-eu-ctf", "siunam321", "nahamcon"]
difficulty: "easy"
summary: "rev writeup for \"Hashstation\" from NahamCon-EU-CTF - techniques: hashstation, reverse-engineering, nahamcon-eu-ctf, siunam321, nahamcon."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Hashstation/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Hashstation/README.md"
ctf:
  name: "NahamCon-EU-CTF"
  year: 2022
  challenge: "Hashstation"
---

## Source

- **CTF:** NahamCon-EU-CTF 2022
- **Challenge:** Hashstation
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Hashstation/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Hashstation/README.md>

---
# Hashstation

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: Easy

## Background

Author: @JohnHammond#6971  
  
Below is a [SHA256](https://en.wikipedia.org/wiki/SHA-2) hash! Can you determine what the original data was, before it was hashes?  
  
`705db0603fd5431451dab1171b964b4bd575e2230f40f4c300d70df6e65f5f1c`  
  
**Please wrap the original value within the `flag{` prefix and `}` suffix to match the standard flag format.**

## Find The Flag

According to the challenge's title, it's clear that **the title is referring to [CrackStation](https://crackstation.net/)! Which is an online tool that lookup all different hashes.**

**Let's throw that SHA256 hash to CrackStation!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216222508.png)

Found it!

- **Flag: `flag{awesome}`**

# Conclusion

What we've learned:

1. Cracking SHA256 Hash via [CrackStation](https://crackstation.net/)
