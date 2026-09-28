---
title: "xss 1 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "web-exploitation", "xss-1", "portswigger-labs", "siunam321"]
summary: "web writeup for \"xss 1\" from portswigger labs - techniques: xss, web-exploitation, xss-1, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "xss 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** xss 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-1/README.md>

---
# Reflected XSS into HTML context with nothing encoded | Dec 29, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded), you'll learn: Reflected XSS into HTML context with nothing encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a simple [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search functionality.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229012907.png)

In here, we can see there is a search box.

**Let's search something:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229012932.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229012947.png)

When we clicked the `Search` button, **it'll send a GET request to `/`, with parameter `search`.**

Also, **our input is reflected to the web page.**

**Let's try to inject a JavaScript function called `alert()`:**
```html
<script>alert(document.domain)</script>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229013240.png)

As you can see, we successfully injected a JavaScript that under attacker's control!

# What we've learned:

1. Reflected XSS into HTML context with nothing encoded
