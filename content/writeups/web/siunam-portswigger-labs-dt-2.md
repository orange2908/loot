---
title: "dt 2 - portswigger labs"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "lfi", "web-exploitation", "dt-2", "portswigger-labs"]
summary: "web writeup for \"dt 2\" from portswigger labs - techniques: path-traversal, lfi, web-exploitation, dt-2, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-2/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-2/README.md"
ctf:
  name: "portswigger labs"
  challenge: "dt 2"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** dt 2
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-2/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-2/README.md>

---
# File path traversal, traversal sequences blocked with absolute path bypass | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass), you'll learn: File path traversal, traversal sequences blocked with absolute path bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-2/images/Pasted%20image%2020221212015318.png)

**In the previous lab, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-2/images/Pasted%20image%2020221212015507.png)

This time however, **the application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.**

To bypass this, **we can just provide the absolute path of the `/etc/passwd`**:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-2/images/Pasted%20image%2020221212015741.png)

# What we've learned:

1. File path traversal, traversal sequences blocked with absolute path bypass
