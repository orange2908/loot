---
title: "blv 9 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "burp", "csrf", "blv", "rsa"]
summary: "crypto writeup for \"blv 9\" from portswigger labs - techniques: wiener, burp, csrf, blv, rsa."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-9/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-9/README.md"
ctf:
  name: "portswigger labs"
  challenge: "blv 9"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** blv 9
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-9/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-9/README.md>

---
# Authentication bypass via flawed state machine | Dec 20, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine), you'll learn: Authentication bypass via flawed state machine! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete Carlos.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220072840.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220072905.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220072932.png)

In here, we can choose a role: User or Content author.

**Let's select User and intercept the request via Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073138.png)

When we clicked the `Select` button, **it'll send a POST request to `/role-selector`, with parameter `role` and `csrf`.**

Let's forward that request and click the `My account` link:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073245.png)

**Now, what if we select Content author role?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073418.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073604.png)

It seems like no difference between those roles.

**Let's try to reach to the admin panel `/admin`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074622.png)

It's only available to administrator.

**Now, let's try to log out and test something:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074726.png)

**Then login and intercept the request via Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074801.png)

**We'll forward the POST `/login` request:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074810.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074843.png)

**In here, what if I drop the GET `/role-selector` request?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074921.png)

**Then go to the home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074956.png)

Hmm... We have admin access!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220075013.png)

Let's delete user `carlos`!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220075028.png)

Nice!

# What we've learned:

1. Authentication bypass via flawed state machine
