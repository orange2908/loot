---
title: "id 1 - portswigger labs"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "web-exploitation", "id-1", "portswigger-labs", "siunam321", "portswigger"]
summary: "web writeup for \"id 1\" from portswigger labs - techniques: web-exploitation, id-1, portswigger-labs, siunam321, portswigger."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Information-Disclosure/id-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Information-Disclosure/id-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "id 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** id 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Information-Disclosure/id-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Information-Disclosure/id-1/README.md>

---
# Information disclosure in error messages | Dec 16, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages), you'll learn: Information disclosure in error messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216051328.png)

In here, we can view the details of each products.

**Let's click on the `View details` button:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216051935.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216051943.png)

In here, we can see there is a GET parameter called `productId`.

**Hmm... What if that parameter is doing a SQL query?**

**If so, we can try to trigger a SQL error via `'`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216052044.png)

Boom! We found it!

- Web application version: `Apache Struts 2 2.3.31`

**In `searchsploit`(An offline version of Exploit-DB), we can see that it's vulnerable to Remote Code Execution(RCE)!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-1]
└─# searchsploit Apache Struts 2 2.3.31
-------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                          |  Path
-------------------------------------------------------------------------------------------------------- ---------------------------------
Apache Struts 2.0.1 < 2.3.33 / 2.5 < 2.5.10 - Arbitrary Code Execution                                  | multiple/remote/44556.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (1)                                   | linux/remote/45260.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (2)                                   | multiple/remote/45262.py
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasploit)    | multiple/remote/41614.rb
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution                                     | linux/webapps/41570.py
-------------------------------------------------------------------------------------------------------- ---------------------------------
```

# What we've learned:

1. Information disclosure in error messages
