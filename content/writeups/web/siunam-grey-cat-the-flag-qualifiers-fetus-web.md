---
title: "Fetus-Web - Grey-Cat-The-Flag Qualifiers 2023"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "fetus-web", "web-exploitation", "grey-cat-the-flag-qualifiers", "siunam321", "fetus"]
summary: "web writeup for \"Fetus-Web\" from Grey-Cat-The-Flag Qualifiers - techniques: fetus-web, web-exploitation, grey-cat-the-flag-qualifiers, siunam321, fetus."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Fetus-Web/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Fetus-Web/README.md"
ctf:
  name: "Grey-Cat-The-Flag Qualifiers"
  year: 2023
  challenge: "Fetus-Web"
---

## Source

- **CTF:** Grey-Cat-The-Flag Qualifiers 2023
- **Challenge:** Fetus-Web
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Fetus-Web/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Fetus-Web/README.md>

---
# Fetus Web

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 368 solves / 50 points
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

A simple web warmup.

- Junhua

[http://34.124.157.94:12325](http://34.124.157.94:12325)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519220330.png)

**View source page:**
```html
[...]
      <!-- End Services Section -->

      <!-- Flag part 1: grey{St3p_1-->

      <!-- ======= Counter Section ======= -->
[...]
```

In here, we see the first part of the flag: `grey{St3p_1`

**Then, we can open up "Debugger" tab to find the second part:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519220454.png)

- **Full flag: `grey{St3p_1_of_b4by_W3b}`**

## Conclusion

What we've learned:

1. Inspecting Source Page
