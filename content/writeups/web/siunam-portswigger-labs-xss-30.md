---
title: "xss 30 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "csp-bypass", "burp", "csp", "web-exploitation"]
summary: "web writeup for \"xss 30\" from portswigger labs - techniques: xss, csp-bypass, burp, csp, web-exploitation."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-30/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-30/README.md"
ctf:
  name: "portswigger labs"
  challenge: "xss 30"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** xss 30
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-30/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-30/README.md>

---
# Reflected XSS protected by CSP, with CSP bypass | Jan 2, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass), you'll learn: Reflected XSS protected by CSP, with CSP bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab uses [CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) and contains a [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that bypasses the CSP and calls the `alert` function.

Please note that the intended solution to this lab is only possible in Chrome.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020418.png)

In here, we can see there is a search box.

Let's search something:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020449.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020504.png)

As you can see, our input is reflected to the web page.

**Burp Suite HTTP history:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020545.png)

**We can see that the CSP (Content Security Policy) is enabled:**
```
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=
```

Notice that **the `script-src` is set to `self`**, which means **only allow JavaScript to be loaded from the same origin as the page itself**.

However, we also can see there is a `report-uri` directive, which **reflects input into the actual policy**.

**If the site reflects a parameter that we can control, we can inject a semicolon to add our own CSP directives.**

Normally, it's not possible to overwrite an existing `script-src` directive. However, Chrome introduced **the `script-src-elem` directive, which allows you to control `script` elements, but not events.** Crucially, this new directive allows you to overwrite existing `script-src` directives.

Armed with above information, **we can try to bypass the CSP by injecting new CSP policy.**

**Payload:**
```
/?token=;script-src-elem 'unsafe-inline'&search=<script>alert(document.domain)</script>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102022207.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102022231.png)

> Note: If you don't see the completed banner, set the `script-src-elem` to `none`.

Nice!

# What we've learned:

1. Reflected XSS protected by CSP, with CSP bypass
