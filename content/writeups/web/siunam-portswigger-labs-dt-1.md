---
title: "dt 1 - portswigger labs"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "burp", "lfi", "web-exploitation", "dt-1"]
summary: "web writeup for \"dt 1\" from portswigger labs - techniques: path-traversal, burp, lfi, web-exploitation, dt-1."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "dt 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** dt 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-1/README.md>

---
# File path traversal, simple case | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-simple), you'll learn: File path traversal, simple case! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212012831.png)

**View-source:**
```html
<section class="ecoms-pageheader">
    <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/shop.svg">
</section>
<section class="container-list-tiles">
    <div>
        <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/image?filename=25.jpg">
        <h3>The Lazy Dog</h3>
        <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/rating2.png">
        $81.33
        <a class="button" href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/product?productId=1">View details</a>
    </div>
    <div>
        <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/image?filename=2.jpg">
        <h3>All-in-One Typewriter</h3>
        <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/rating1.png">
        $50.04
        <a class="button" href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/product?productId=2">View details</a>
    </div>
    [...]
```

**As you can see, the `img` tag's attribute `src` is using a GET parameter called `filename`.**

**This might be vulnerable to path traversal!**

**Let's open one of those product images:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212013215.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212013226.png)

Hmm... **What if I can use the `../` to move up a directory level and try to retrieve `/etc/passwd` file?**

**To do so, I'll intercept the request via Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212013942.png)

**When we move up 1 directory level, it outputs `No such file`. Let's move up more directory levels until we retrieved the `/etc/passwd` file!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212014008.png)

**When we move up 3 directory levels, it sucessfully retrieved the `/etc/passwd`'s content!!**

# What we've learned:

1. File path traversal, simple case
