---
title: "ac 3 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "rsa", "cryptography", "ac-3", "portswigger-labs"]
summary: "crypto writeup for \"ac 3\" from portswigger labs - techniques: wiener, rsa, cryptography, ac-3, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-3/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-3/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 3"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 3
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-3/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-3/README.md>

---
# User role controlled by request parameter | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter), you'll learn: User role controlled by request parameter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212043834.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212043857.png)

**In the lab background, it said:**

> This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

**Let's view our cookies!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044006.png)

As you can see, there is a cookie called `Admin`, and it's value is `false`.

**Hmm... What if I change the value to `true`?? Will I become an administrator??**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044107.png)

**Now let's go to the admin panel at `/admin`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044139.png)

I'm allowed to go to the admin panel!

Let's delete user `carlos`!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044213.png)

# What we've learned:

1. User role controlled by request parameter
