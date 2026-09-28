---
title: "dt 6 - portswigger labs"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "lfi", "web-exploitation", "dt-6", "portswigger-labs"]
summary: "web writeup for \"dt 6\" from portswigger labs - techniques: path-traversal, lfi, web-exploitation, dt-6, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-6/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-6/README.md"
ctf:
  name: "portswigger labs"
  challenge: "dt 6"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** dt 6
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-6/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-6/README.md>

---
# File path traversal, validation of file extension with null byte bypass | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass), you'll learn: File path traversal, validation of file extension with null byte bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application validates that the supplied filename ends with the expected file extension.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-6/images/Pasted%20image%2020221212023150.png)

**In the previous labs, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-6/images/Pasted%20image%2020221212023240.png)

**Also, in the lab background, it said:**

> The application validates that the supplied filename ends with the expected file extension.

**To bypass that, we can use a null byte(`%00`) to remove the file extension:**
```
/image?filename=../../../etc/passwd%00.png
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-6/images/Pasted%20image%2020221212023458.png)

# What we've learned:

1. File path traversal, validation of file extension with null byte bypass
