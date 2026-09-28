---
title: "ac 8 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "burp", "rsa", "cryptography", "ac-8"]
summary: "crypto writeup for \"ac 8\" from portswigger labs - techniques: wiener, burp, rsa, cryptography, ac-8."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-8/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-8/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 8"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 8
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-8/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-8/README.md>

---
# User ID controlled by request parameter with password disclosure | Dec 14, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure), you'll learn: User ID controlled by request parameter with password disclosure! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has user account page that contains the current user's existing password, prefilled in a masked input.

To solve the lab, retrieve the administrator's password, then use it to delete `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014231.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014250.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014257.png)

**In the previous labs, we found that the `My account` link is supplying an `id` GET parameter:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014558.png)

This time however, we also can see we can update our own password, and **it's prefilled in a masked input**.

**Hmm... Can we inspect that password?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014659.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014713.png)

Cool, we can see our own password.

**How about using the `My account` link to view another user's password? Like `administrator`:**

**To do so, I'll use Burp Suite's Repeater:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014837.png)

**Now, we can view `administrator`' password! `bdxywccjia4y27fb9yty`. Let's login as `administrator` and delete user `carlos`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014941.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014955.png)

We found the `Admin panel`!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214015015.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214015024.png)

# What we've learned:

1. User ID controlled by request parameter with password disclosure
