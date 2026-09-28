---
title: "dt 5 - portswigger labs"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "lfi", "web-exploitation", "dt-5", "portswigger-labs"]
summary: "web writeup for \"dt 5\" from portswigger labs - techniques: path-traversal, lfi, web-exploitation, dt-5, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-5/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-5/README.md"
ctf:
  name: "portswigger labs"
  challenge: "dt 5"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** dt 5
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-5/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-5/README.md>

---
# File path traversal, validation of start of path | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path), you'll learn: File path traversal, validation of start of path! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-5/images/Pasted%20image%2020221212022347.png)

**In the previous labs, we found that there is a file path trvaersal vulnerability in the display of product images:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-5/images/Pasted%20image%2020221212022450.png)

**Also, in the lab background, it said:**

> The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

**To bypass that, we must go back to the `/` root file system:**
```
/image?filename=/var/www/images/../../../etc/passwd
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-5/images/Pasted%20image%2020221212022728.png)

# What we've learned:

1. File path traversal, validation of start of path
