---
title: "cache 2 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "cache-poisoning", "burp", "cache", "web-exploitation"]
summary: "web writeup for \"cache 2\" from portswigger labs - techniques: xss, cache-poisoning, burp, cache, web-exploitation."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-2/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Web-Cache-Poisoning/cache-2/README.md"
ctf:
  name: "portswigger labs"
  challenge: "cache 2"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** cache 2
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-2/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Web-Cache-Poisoning/cache-2/README.md>

---
# Web cache poisoning with an unkeyed cookie | Jan 23, 2023

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie), you'll learn: Web cache poisoning with an unkeyed cookie! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(1)` in the visitor's browser.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-2/images/Pasted%20image%2020230123175018.png)

Burp Suite HTTP history:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-2/images/Pasted%20image%2020230123175052.png)

In here, we see that the web application is using caches to cache the web content.

**View source page:**
```html
[...]
<script>
    data = {
        "host":"0a1d00f203641c33c0c9181100f000ca.web-security-academy.net",
        "path":"/",
        "frontend":"prod-cache-01"
    }
</script>
[...]
```

We also see that there is a JavaScript code.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-2/images/Pasted%20image%2020230123175330.png)

In the second request, it'll set a new cookie called `fehost`, with the value of `frontend` in the above JavaScript code.

Now, let's test if can we control the `frontend` key's value by modifying the `fehost` cookie:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-2/images/Pasted%20image%2020230123180042.png)

> Note: To prevent other users are being affected by our testing payload, we can use cache buster, which basically adding a random GET parameter.

As you can see, we can control it!

**What if I change the `fehost` cookie to an XSS payload?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-2/images/Pasted%20image%2020230123180447.png)

**Then, keep sending the request until it gets cached, and go to `/?buster=buster1`:** 

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-2/images/Pasted%20image%2020230123180538.png)

We triggered an XSS payload!

**Let's remove the cache buster and cache our XSS payload to the victim!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-2/images/Pasted%20image%2020230123180658.png)

# What we've learned:

1. Web cache poisoning with an unkeyed cookie
