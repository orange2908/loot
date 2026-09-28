---
title: "Responsive - GuidePoint-Security-Oct27 2022"
category: "web"
subcategory: "nosqli"
type: "writeup"
tags: ["web", "nosql-injection", "burp", "responsive", "nosqli", "web-exploitation"]
summary: "In this challenge, we can spawn a docker instance:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Responsive/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Responsive/README.md"
ctf:
  name: "GuidePoint-Security-Oct27"
  year: 2022
  challenge: "Responsive"
---

## Source

- **CTF:** GuidePoint-Security-Oct27 2022
- **Challenge:** Responsive
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Responsive/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Responsive/README.md>

---
# Responsive

## Overview

- Overall difficulty for me: Medium

**In this challenge, we can spawn a docker instance:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004634.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004710.png)

We're prompt to a login page!

**We can try to guess the username and password:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004943.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029005021.png)

Hmm... No luck.

If you look carefully in the header: **`No Login`, and a login prompt.**

This got me thinking: **Is this about NoSQL injection authentication bypass??**

**According to [this blog](https://www.varutra.com/nosql-injection-vulnerability/), we can bypass it via `[$ne]`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012047.png)

**Let's fire up Burp Suite and capture the POST request!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012114.png)

**Modify the POST value and forward the request:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012139.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012210.png)

We're in!

# Conclusion

What we've learned:

1. Authentication Bypass via NoSQL Injection
