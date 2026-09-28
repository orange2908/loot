---
title: "Figgis - GuidePoint-Security-Oct27 2022"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "command-injection", "gobuster", "figgis", "rce", "web-exploitation"]
summary: "In this challenge, we can spawn a docker instance:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Figgis/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Figgis/README.md"
ctf:
  name: "GuidePoint-Security-Oct27"
  year: 2022
  challenge: "Figgis"
---

## Source

- **CTF:** GuidePoint-Security-Oct27 2022
- **Challenge:** Figgis
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Figgis/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Figgis/README.md>

---
# Figgis

## Overview

- Overall difficulty for me: Easy

**In this challenge, we can spawn a docker instance:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030032809.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030032845.png)

**Seems like nothing here, let's enumerate hidden directory via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Figgis]
└─# gobuster dir -u http://10.10.100.200:54221/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php
[...]
/config               (Status: 200) [Size: 516]
/cookie               (Status: 200) [Size: 333]
/evaluate             (Status: 200) [Size: 322]
/lookup               (Status: 200) [Size: 315]
/xml                  (Status: 200) [Size: 311]
```

Let's check all of them!

**`/config`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030033950.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034000.png)

**Bad padding?**

**`cookie`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034026.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034034.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034045.png)

Seems useless?

**`/evaluate`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034139.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034146.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034152.png)

**Hmm... We can input something to execute codes.**

I tried to execute code, but no dice.

**`/lookup`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034744.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034812.png)

**Hmm... What if it's vulnerable to command injection?**

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection#command-injection-execution), we can try some payloads:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035033.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035049.png)

**Oh! It works! Let's find out the flag!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035123.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035145.png)

We got the flag!

# Conclusion

What we've learned:

1. Exploiting Command Injection
