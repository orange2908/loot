---
title: "cache 1 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "cache-poisoning", "burp", "reverse-proxy", "cache"]
summary: "web writeup for \"cache 1\" from portswigger labs - techniques: xss, cache-poisoning, burp, reverse-proxy, cache."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Web-Cache-Poisoning/cache-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "cache 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** cache 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Web-Cache-Poisoning/cache-1/README.md>

---
# Web cache poisoning with an unkeyed header | Jan 22, 2023

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header), you'll learn: Web cache poisoning with an unkeyed header! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122173716.png)

Burp Suite HTTP history:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122173923.png)

In here, we see that the web server is using web cache. We can try to exploit web cache poisoning.

**View source page:**
```html
<script type="text/javascript" src="//0aac000d032848eac0a590ea0070009e.web-security-academy.net/resources/js/tracking.js"></script>
```

In here, this imported JavaScript is weird to me, as **the `src` attribute is referring to a domain**.

**After some fumbling, I found that the web application accepts unkeyed `X-Forwarded-Host` HTTP header:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122174709.png)

> Note: To prevent other users are being affected by our testing payload, we can use cache buster, which basically adding a random GET parameter.

We can inject anything we want to the `src` attribute is the imported `tracking.js` script file!

**Armed with above information, we can inject a JavaScript that executes `alert(document.cookie)` in our browser!**
```html
"></script><img src=errorpls onerror=alert(document.cookie)>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175643.png)

Nice!

Next, we need to posion the web cache.

To do so, I'll **send the XSS payload request multiple times, until the cache is hit:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175732.png)

**Then, we can go to `/?buster=buster1` without the XSS payload:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175749.png)

Cool!

**Now, we can really posion the home page by removing the cache buster, and repeat the previous step!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175916.png)

When the victim visit the home page, it'll trigger our XSS payload!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175939.png)

# What we've learned:

1. Web cache poisoning with an unkeyed header
