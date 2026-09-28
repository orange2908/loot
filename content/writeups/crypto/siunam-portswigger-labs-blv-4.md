---
title: "blv 4 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "blv", "rsa", "cryptography", "blv-4"]
summary: "crypto writeup for \"blv 4\" from portswigger labs - techniques: wiener, blv, rsa, cryptography, blv-4."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-4/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-4/README.md"
ctf:
  name: "portswigger labs"
  challenge: "blv 4"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** blv 4
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-4/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-4/README.md>

---
# Flawed enforcement of business rules | Dec 19, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules), you'll learn: Flawed enforcement of business rules! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070135.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070205.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070222.png)

In here, we can see that **there is a code: `NEWCUST5`.**

**Let's try to buy the leather jacket:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070407.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070425.png)

**Then go to `/cart` page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070501.png)

**Now, let's try to apply the `NEWCUST5` coupon:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070529.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070605.png)

Now the total price is reduced by 5 dollars!

**Hmm... What if we can apply infinite amount of that coupon??**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219070733.png)

Well, we can't do that. Let's remove that item from our cart.

**After poking around the web site, I found that there is a newsletter subscription:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219071507.png)

Let's try to sign up!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219071523.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219071552.png)

We have 1 more coupon! `SIGNUP30`

**Hmm... Let's add the leather jacket to our cart, and test the coupon again:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219071735.png)

**Again, let's try to apply the coupon again:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219071809.png)

Wait what? We can apply duplicate coupons!**

**Let's apply those coupons until the total price is below `$100.00`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219072023.png)

Let's click the `Place order` button!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-4/images/Pasted%20image%2020221219072048.png)

We did it!

# What we've learned:

1. Flawed enforcement of business rules
