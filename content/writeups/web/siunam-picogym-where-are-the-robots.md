---
title: "where are the robots - picoGym"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "robots", "web-exploitation", "where-are-the-robots", "picogym", "siunam321"]
summary: "web writeup for \"where are the robots\" from picoGym - techniques: robots, web-exploitation, where-are-the-robots, picogym, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/picoGym/Web-Exploitation/where-are-the-robots/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/picoGym/Web-Exploitation/where-are-the-robots/README.md"
ctf:
  name: "picoGym"
  challenge: "where are the robots"
---

## Source

- **CTF:** picoGym
- **Challenge:** where are the robots
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/picoGym/Web-Exploitation/where-are-the-robots/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/picoGym/Web-Exploitation/where-are-the-robots/README.md>

---
# where are the robots | Mar 3, 2023

## Introduction

Welcome to my another writeup! In this picoGym [challenge](https://play.picoctf.org/practice/challenge/4?category=1&page=1&solved=0), you'll learn: Reading web crawler file (`robots.txt`)! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Author: zaratec/Danny

Description

Can you find the robots? `https://jupiter.challenges.picoctf.org/problem/60915/` ([link](https://jupiter.challenges.picoctf.org/problem/60915/)) or http://jupiter.challenges.picoctf.org:60915

## Enumeration

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/picoGym/Web-Exploitation/where-are-the-robots/images/Pasted%20image%2020230303182311.png)

Pretty empty.

In the challenge's title and the home page, it's referring to a file called `robots.txt`, which is a file for web crawler (an Internet bot that systematically browses the World Wide Web).

**Let's try to read that file:**
```shell
┌[siunam♥earth]-(~/ctf/picoGym/Web-Exploitation)-[2023.03.03|18:14:29(HKT)]
└> curl https://jupiter.challenges.picoctf.org/problem/60915/robots.txt                           
User-agent: *
Disallow: /8028f.html
```

As you can see, **it's disallowing web crawler (not us) to view `/8028f.html`.**

**Let's go there!**
```shell
┌[siunam♥earth]-(~/ctf/picoGym/Web-Exploitation)-[2023.03.03|18:25:41(HKT)]
└> curl -s https://jupiter.challenges.picoctf.org/problem/60915/8028f.html | html2text

Guess you found the robots
picoCTF{ca1cu1at1ng_Mach1n3s_8028f}
```

We found the flag!

- **Flag: `picoCTF{ca1cu1at1ng_Mach1n3s_8028f}`**

# What we've learned:

1. where are the robots
