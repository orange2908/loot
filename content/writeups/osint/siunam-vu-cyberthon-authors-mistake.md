---
title: "Authors mistake - VU-Cyberthon 2023"
category: "osint"
subcategory: "osint"
type: "writeup"
tags: ["osint", "authors", "mistake", "open-source-intelligence", "authors-mistake", "vu-cyberthon"]
summary: "In this challenge, we have a link, which points to a Pinterest's picture:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/VU-Cyberthon-2023/OSINT/Authors-mistake/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/OSINT/Authors-mistake/README.md"
ctf:
  name: "VU-Cyberthon"
  year: 2023
  challenge: "Authors mistake"
---

## Source

- **CTF:** VU-Cyberthon 2023
- **Challenge:** Authors mistake
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/VU-Cyberthon-2023/OSINT/Authors-mistake/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/OSINT/Authors-mistake/README.md>

---
# Authors mistake

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150819.png)

## Find the flag

**In this challenge, we have a [link](https://www.pinterest.com/pin/964051863962640190/), which points to a Pinterest's picture:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150858.png)

**Let's click on that user profile:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150913.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150921.png)

In here, there are 4 more images.

**Let's look at the last one:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150952.png)

Boom! We found the flag!

- **Flag: `VU{179d9afbd6a5a817ca2765ab958ba9d8ec95eb7c}`**

# Conclusion

What we've learned:

1. Viewing Pinterest Comments
