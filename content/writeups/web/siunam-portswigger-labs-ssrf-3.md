---
title: "ssrf 3 - portswigger labs"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "web-exploitation", "ssrf-3", "portswigger-labs", "siunam321"]
summary: "web writeup for \"ssrf 3\" from portswigger labs - techniques: ssrf, web-exploitation, ssrf-3, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-3/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-3/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ssrf 3"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ssrf 3
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-3/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-3/README.md>

---
# SSRF with blacklist-based input filter | Dec 24, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter), you'll learn: SSRF with blacklist-based input filter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

The developer has deployed two weak anti-SSRF defenses that you will need to bypass.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224025549.png)

In the previous labs, we found that **the stock check feature has a Server-Side Request Forgery(SSRF) vulnerability:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224025641.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224025849.png)

We clicked the `Check stock` button, **it'll send a POST request to `/product/stock`, with parameter `stockApi`, and it's value is interesting:**

**URL decoded:**
```
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

**Now, what if I change the domain to `localhost`?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030030.png)

It gets blocked.

**How about `127.0.0.1`?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030102.png)

Same.

**To bypass this filter, we can use refer to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#localhost):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030233.png)

**Let's use `127.1`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030931.png)

Hmm... Still getting blocked.

**Maybe the application is checking the word `admin`?**

**If in that case, we can obfuscate that word:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031030.png)

Nice! We now can reach the admin panel.

**Let's delete user `carlos`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031100.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031124.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031130.png)

We did it!

# What we've learned:

1. SSRF with blacklist-based input filter
