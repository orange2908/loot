---
title: "ssrf 1 - portswigger labs"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "burp", "web-exploitation", "ssrf-1", "portswigger-labs"]
summary: "web writeup for \"ssrf 1\" from portswigger labs - techniques: ssrf, burp, web-exploitation, ssrf-1, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ssrf 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ssrf 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Server-Side-Request-Forgery/ssrf-1/README.md>

---
# Basic SSRF against the local server | Dec 24, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost), you'll learn: Basic SSRF against the local server! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015447.png)

**Let's view one of those products detail:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015521.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015534.png)

In here, we can see that users are allowed to check the stock.

**Let's click the `Check stock` button, and intercept the request via Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015648.png)

When we clicked the `Check stock` button, **it'll send a POST request to `/product/stock`, with parameter `stockApi` and it's value is interesting:**

**URL decoded:**
```
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

As you can see, it's sending a request to an **internal** API.

**What if I change the domain to `localhost`, and forward the request?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015938.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015953.png)

**Oh! It displays the home page, and it has an admin panel!**

Armed with above information, it's clear that this **check stock function is vulnerable to Server-Side Request Forgery(SSRF)!**

**However, when we clicked the `admin panel` link:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020125.png)

It's only available to adminsitrator or **request from localhost**!

**Let's change our SSRF payload to `http://localhost/admin`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020313.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020324.png)

We can see the admin panel! Let's try to delete user `carlos`!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020355.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020412.png)

**Again, we need to do it from the SSRF payload:**
```
http://localhost/admin/delete?username=carlos
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020450.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020501.png)

We did it!

# What we've learned:

1. Basic SSRF against the local server
