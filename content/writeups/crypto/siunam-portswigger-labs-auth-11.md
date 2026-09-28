---
title: "auth 11 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "burp", "reverse-proxy", "auth", "rsa"]
summary: "crypto writeup for \"auth 11\" from portswigger labs - techniques: wiener, burp, reverse-proxy, auth, rsa."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-11/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-11/README.md"
ctf:
  name: "portswigger labs"
  challenge: "auth 11"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** auth 11
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-11/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-11/README.md>

---
# Password reset poisoning via middleware | Dec 22, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware), you'll learn: Password reset poisoning via middleware! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

## Exploitation

**Login page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050152.png)

**Let's login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050224.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050240.png)

**Now, let's try to reset our password in the forgot password link:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050308.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050413.png)

**Email client:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050434.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050520.png)

**Burp Suite HTTP history:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050537.png)

When we clicked the `submit` button, **it'll send a POST request to `/forgot-password` and a token, with parameter `temp-forgot-password-token`, `new-password-1`, and `new-password-2`.**

Let's try to add a HTTP header called `X-Forwarded-Host`. If the application accepts that HTTP header, we can know that the the reset email is generated dynamically.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222051638.png)

It worked!

Armed with aboe information, the reset email function may vulnerable to **password reset poisoning**, as attackers can dynamically generated reset link to an arbitrary domain.

**To do so, I'll change parameter `username` value to `carlos`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222051937.png)

**Exploit server access log:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052007.png)

- Carlos password reset token: `mjTcAhTKUiFHCw1vGZnpxd5PBHhY8zXb`

**Now, we can send a POST request to `/forgot-password` with the new token!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052228.png)

In here, we should able to login as `carlos`!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052255.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052300.png)

We're user `carlos`!

# What we've learned:

1. Password reset poisoning via middleware
