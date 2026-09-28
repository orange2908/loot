---
title: "id 3 - portswigger labs"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "web-exploitation", "id-3", "portswigger-labs", "siunam321", "portswigger"]
summary: "web writeup for \"id 3\" from portswigger labs - techniques: web-exploitation, id-3, portswigger-labs, siunam321, portswigger."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Information-Disclosure/id-3/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Information-Disclosure/id-3/README.md"
ctf:
  name: "portswigger labs"
  challenge: "id 3"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** id 3
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Information-Disclosure/id-3/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Information-Disclosure/id-3/README.md>

---
# Source code disclosure via backup files | Dec 16, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files), you'll learn: Information disclosure in error messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-3/images/Pasted%20image%2020221216053654.png)

**In `robots.txt`, I found something interesting:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-3]
└─# curl https://0a130056031f083bc036cc3700250088.web-security-academy.net/robots.txt             
User-agent: *
Disallow: /backup
```

> `robots.txt` is a plaintext file that let robots(crawlers) know which page shouldn't be indexed.

**Let's go there:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-3/images/Pasted%20image%2020221216053943.png)

Found a backup file! `ProductTemplate.java.bak`.

**We can download it via `wget`:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-3]
└─# wget https://0a130056031f083bc036cc3700250088.web-security-academy.net/backup/ProductTemplate.java.bak
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-3/images/Pasted%20image%2020221216054125.png)

**This random string looks like the password for the PostgresSQL database!**

# What we've learned:

1. Source code disclosure via backup files
