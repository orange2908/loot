---
title: "dt 3 - portswigger labs"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "lfi", "web-exploitation", "dt-3", "portswigger-labs"]
summary: "web writeup for \"dt 3\" from portswigger labs - techniques: path-traversal, lfi, web-exploitation, dt-3, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-3/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-3/README.md"
ctf:
  name: "portswigger labs"
  challenge: "dt 3"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** dt 3
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Directory-Traversal/dt-3/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Directory-Traversal/dt-3/README.md>

---
# File path traversal, traversal sequences stripped non-recursively | Dec 12, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively), you'll learn: File path traversal, traversal sequences stripped non-recursively! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application strips [path traversal](https://portswigger.net/web-security/file-path-traversal) sequences from the user-supplied filename before using it.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-3/images/Pasted%20image%2020221212020318.png)

**In previous labs, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-3/images/Pasted%20image%2020221212020440.png)

**In the background, it said:**

> The application strips path traversal sequences from the user-supplied filename before using it.

**To bypass that, we can use nested traversal sequences, like `....//`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Directory-Traversal/DT-3/images/Pasted%20image%2020221212020647.png)

# What we've learned:

1. File path traversal, traversal sequences stripped non-recursively
