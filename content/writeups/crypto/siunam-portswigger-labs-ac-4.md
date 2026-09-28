---
title: "ac 4 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "burp", "rsa", "cryptography", "ac-4"]
summary: "crypto writeup for \"ac 4\" from portswigger labs - techniques: wiener, burp, rsa, cryptography, ac-4."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-4/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-4/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 4"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 4
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-4/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-4/README.md>

---
# User role can be modified in user profile | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile), you'll learn: User role can be modified in user profile! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of 2.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212044715.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212044735.png)

**In here, we can `Update email`. Let's intercept that request in Burp Suite's Repeater!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212045522.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212050356.png)

**It's sending a POST request to `/my-account/change-email`, and contain a JSON data with our supplied email address.**

**Also, when we send the POST request, we can see the response is:**
```json
{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "apikey": "Qvbkfk3gByoLDZrgkvPw43om5BsJC7nz",
  "roleid": 1
}
```

**Hmm... What if I set the `roleid` to 2?? Which is suppose to be user `administrator`!**
```json
{
  "email":"wiener@normal-user.net",
  "roleid": 2
}
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212051310.png)

**Now, let's try to go to the admin panel (`/admin`):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212050743.png)

We can access the admin panel!!

Let's delete user `carlos`!!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212050810.png)

# What we've learned:

1. User role can be modified in user profile
