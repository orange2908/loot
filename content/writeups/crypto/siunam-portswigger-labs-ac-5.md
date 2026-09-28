---
title: "ac 5 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "privesc", "rsa", "cryptography", "ac-5"]
summary: "crypto writeup for \"ac 5\" from portswigger labs - techniques: wiener, privesc, rsa, cryptography, ac-5."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-5/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-5/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 5"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 5
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-5/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-5/README.md>

---
# User ID controlled by request parameter | Dec 14, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter), you'll learn: User ID controlled by request parameter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a horizontal privilege escalation vulnerability on the user account page.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214005344.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214005504.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214005516.png)

**Let's view the source!**
```html
[...]
<section class="top-links">
    <a href=/>Home</a><p>|</p>
    <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/my-account?id=wiener">My account</a><p>|</p>
    <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/logout">Log out</a><p>|</p>
</section>
[...]
```

In here, we can see the `/my-account` page can supply an `id` GET parameter!

**What if I change it to another users? Like user `carlos`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214010104.png)

**Boom! I'm user `carlos`, and found his API key!**

# What we've learned:

1. User ID controlled by request parameter
