---
title: "ac 13 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "burp", "rsa", "cryptography", "ac-13"]
summary: "crypto writeup for \"ac 13\" from portswigger labs - techniques: wiener, burp, rsa, cryptography, ac-13."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-13/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-13/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 13"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 13
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-13/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-13/README.md>

---
# Referer-based access control | Dec 14, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-referer-based-access-control), you'll learn: Referer-based access control! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab controls access to certain admin functionality based on the Referer header. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed [access controls](https://portswigger.net/web-security/access-control) to promote yourself to become an administrator.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033356.png)

**Let's login as `administrator` to view the admin panel:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033541.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033551.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033602.png)

**In here, we can see an adminstrator level user can upgrade or downgrade a user's privilege.**

**Let's try to upgrade a user privilege, and intercept that request via Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033804.png)

**When an administrator try to upgrade a user, it'll send a GET request to `/admin-roles`, with the parameter: `username` and `action` (`upgrade`/`downgrade`).**

**Also, it includes a `Referer` HTTP header!**

**Armed with above information, we can login as user `wiener`, and try to escalate our privilege to administrator:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034022.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034031.png)

**Now, we can try to send a GET request to `/admin-roles` via Burp Suite's Repeater:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034137.png)

However, we get `Unauthorized` error.

In the above GET request, we can see that it includes a `Referer` HTTP header.

**What if I change that to `/admin`? Which is the admin panel location:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034313.png)

Nice! This time we don't have `Unauthorized` error!

**Let's refresh the page and verify we're administrator or not:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034403.png)

We're administrator!!

# What we've learned:

1. Referer-based access control
