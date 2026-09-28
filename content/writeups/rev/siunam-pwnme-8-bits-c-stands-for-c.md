---
title: "C-Stands-For-C - PwnMe 8 bits 2023"
category: "rev"
subcategory: "image"
type: "writeup"
tags: ["rev", "pie", "lsb", "cyberchef", "c-stands-for-c", "image"]
summary: "So I heard about a secret shop who uses a strong password, but it seems like they forgot you were even stronger !"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C/README.md"
ctf:
  name: "PwnMe 8 bits"
  year: 2023
  challenge: "C-Stands-For-C"
---

## Source

- **CTF:** PwnMe 8 bits 2023
- **Challenge:** C-Stands-For-C
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C/README.md>

---
# C Stands For C

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 306 solves / 50 points
- Difficulty: Intro
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

> Author: Zerotistic#0001

So I heard about a secret shop who uses a strong password, but it seems like they forgot you were even stronger ! Hey, if you find the password I'll give you a flag. Sounds good? Sweet!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506141006.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/Reverse/C-Stands-For-C/c_stands_for_c):**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C)-[2023.05.06|14:10:26(HKT)]
└> file c_stands_for_c 
c_stands_for_c: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6e85bb68ae41114c0b985f48263414ae9c715507, for GNU/Linux 3.2.0, not stripped
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C)-[2023.05.06|14:10:28(HKT)]
└> chmod +x c_stands_for_c
```

It's an ELF 64-bit executable, and it's not stripped.

**We can try to run that executable:**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C)-[2023.05.06|14:10:30(HKT)]
└> ./c_stands_for_c 
Hi, please provide the password:
idk
Who are you? What is your purpose here?
```

That being said, we need to find the correct password.

**To do so, I'll use `strings` command in Linux to list out all the strings inside that binary:**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/C-Stands-For-C)-[2023.05.06|14:11:52(HKT)]
└> strings c_stands_for_c
[...]
Hi, please provide the password:
JQHGY{Qbs_x1x_S0o_f00E_b3l3???y65zx03}
Welcome to the shop.
Who are you? What is your purpose here?
[...]
```

Right off the bat, we see a string that looks like a flag. However, it's being rotated.

**We can use [CyberChef](https://gchq.github.io/CyberChef/) to rotate it back:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506141355.png)

- **Flag: `PWNME{Why_d1d_Y0u_l00K_h3r3???e65fd03}`**

## Conclusion

What we've learned:

1. Using `strings` To Display Strings In A File & Rotating Rotated String
