---
title: "xss 2 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "web-exploitation", "xss-2", "portswigger-labs", "siunam321"]
summary: "web writeup for \"xss 2\" from portswigger labs - techniques: xss, web-exploitation, xss-2, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-2/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-2/README.md"
ctf:
  name: "portswigger labs"
  challenge: "xss 2"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** xss 2
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-2/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-2/README.md>

---
# Stored XSS into HTML context with nothing encoded | Dec 29, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded), you'll learn: Stored XSS into HTML context with nothing encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229013949.png)

**In the home page, we can view other posts:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014009.png)

**And we can leave a comment:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014016.png)

**Let's try to injection some HTML code in the `comment` field:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014122.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014140.png)

**As you can see, our input became a real HTML tag!**
```html
<section class="comment">
    <p>
    <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/avatarDefault.svg" class="avatar">                            test | 29 December 2022
    </p>
    <p><h1>Header1</h1></p>
    <p></p>
</section>
```

**Now, try to injection a JavaScript function called `alert()`:**
```html
<script>alert(document.domain)</script>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014310.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014323.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014330.png)

Now whoever view this post, they will trigger our `alert()` JavaScript function, as our comment has been stored to the web application's database!

# What we've learned:

1. Stored XSS into HTML context with nothing encoded
