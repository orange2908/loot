---
title: "auth 2 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "auth", "rsa", "cryptography", "auth-2"]
summary: "crypto writeup for \"auth 2\" from portswigger labs - techniques: wiener, auth, rsa, cryptography, auth-2."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-2/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-2/README.md"
ctf:
  name: "portswigger labs"
  challenge: "auth 2"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** auth 2
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-2/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-2/README.md>

---
# 2FA simple bypass | Dec 21, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass), you'll learn: 2FA simple bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials: `wiener:peter`
- Victim's credentials `carlos:montoya`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061118.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061200.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061211.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061305.png)

In here, we're prompted to another login page, which requires a 4 digits security code.

**Email client:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061550.png)

**Enter 4 digits security code:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061602.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061617.png)

**Now let's login as user `carlos` and bypass the 2FA:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061724.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061733.png)

In here, since we're already logged in via a valid username and password, we're technically logged in!

**Why not just go to `/my-account` page?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061810.png)

Nice! The application doesn't check we have entered a valid 2FA code or not!

# What we've learned:

1. 2FA simple bypass
