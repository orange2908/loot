---
title: "ac 1 - portswigger labs"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "web-exploitation", "ac-1", "portswigger-labs", "siunam321", "portswigger"]
summary: "web writeup for \"ac 1\" from portswigger labs - techniques: web-exploitation, ac-1, portswigger-labs, siunam321, portswigger."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-1/README.md>

---
# Unprotected admin functionality | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality), you'll learn: Unprotected admin functionality! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has an unprotected admin panel.

Solve the lab by deleting the user `carlos`.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-1/images/Pasted%20image%2020221212041157.png)

**Let's enumerate this website!**

**`robots.txt`:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Access-Control/AC-1]
└─# curl https://0a4e00f2031a5e0fc2357d45006100d2.web-security-academy.net/robots.txt            
User-agent: *
Disallow: /administrator-panel
```

**In `robots.txt`, we can see that it's disallowing all bots to index `/administrator-panel`!**

**How about we can directly access to that admin panel??**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-1/images/Pasted%20image%2020221212041432.png)

**Hmm... Looks like we can! Let's delete user `carlos`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-1/images/Pasted%20image%2020221212041459.png)

# What we've learned:

1. Unprotected admin functionality
