---
title: "blv 1 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "burp", "csrf", "blv", "rsa"]
summary: "crypto writeup for \"blv 1\" from portswigger labs - techniques: wiener, burp, csrf, blv, rsa."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "blv 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** blv 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-1/README.md>

---
# Excessive trust in client-side controls | Dec 19, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls), you'll learn: Excessive trust in client-side controls! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219045817.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219045909.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219045914.png)

**Let's go to the `/cart` page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050159.png)

As you can see, **we only have `$100` store credit.**

**In the lab background, we need to buy the product `Lightweight l33t leather jacket`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050328.png)

**Let's click `view detail`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050347.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050355.png)

**Now, we can click the `Add to cart` button, and intercept the request via Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050511.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050532.png)

When we clicked that button, **it'll send a POST request to `/cart` with parameter: `productId=1`, `redir=PRODUCT`, `quantity=1`, and `price=133700`.**

**Let's forward that request, and go to `/cart` page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050808.png)

In here, we see that the product has been added to our cart.

**Let's try to click `Place order` button:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050911.png)

When we clicked the `Place order` button, **it'll send a POST request to `/cart/checkout` with a parameter `csrf`.**

**Let's forward that request and see what will happen:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051038.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051150.png)

When we don't have enough store credit to buy a product, **it'll send a GET request to `/cart` with parameter `err`, and it's value is `INSUFFICIENT_FUNDS`.**

**To exploit the application logic flaw, we need to `Remove` the product first:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051306.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051339.png)

When we clicked the `Remove` button, **it'll send a POST request to `/cart`, with parameter `productId=1`, `quantity=-1`, `redir=CART`.**

It seems like the parameter `redir` is redirecting to which page, like `/cart` for example.

**Now, let's go back to the product `Lightweight l33t leather jacket` page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051658.png)

**Hmm... What if I set the price to 100($1.00)?**

**Let's modify and forward the request:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051729.png)

**Then go to `/cart` page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051824.png)

**As we can see, that price changed from `$1337.00` to `$1.00`!!**

**Let's click the `Place order` button:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051913.png)

There is no error anymore!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051959.png)

And we successfully purchased that product!

# What we've learned:

1. Excessive trust in client-side controls
