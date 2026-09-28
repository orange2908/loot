---
title: "Simple-Web - VU-Cyberthon 2023"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "simple-web", "web-exploitation", "vu-cyberthon", "siunam321", "simple"]
summary: "In this challenge, we can download a file:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/VU-Cyberthon-2023/Web-Exploitation/Simple-Web/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/Web-Exploitation/Simple-Web/README.md"
ctf:
  name: "VU-Cyberthon"
  year: 2023
  challenge: "Simple-Web"
---

## Source

- **CTF:** VU-Cyberthon 2023
- **Challenge:** Simple-Web
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/VU-Cyberthon-2023/Web-Exploitation/Simple-Web/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/Web-Exploitation/Simple-Web/README.md>

---
# Simple Web

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150318.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Web/Simple-Web)-[2023.02.25|15:02:55(HKT)]
└> file Task-www.zip 
Task-www.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Web/Simple-Web)-[2023.02.25|15:02:57(HKT)]
└> unzip Task-www.zip              
Archive:  Task-www.zip
  inflating: Task-www-index.html
```

**Task-www-index.html:**
```html
<html>
    <head>
        <meta http-equiv="refresh" WWW-Authenticate="--[----->+<]>---.-[--->+<]>+++.---[->+++<]>.+++.+++++++++++++.++.------------.+++++++.-." sop="WWW-Authenticate in esoteric programming language" content="1;url=https://www.cyberthon.lt/">
    </head>
    <body>
        <h1>Redirecting in 1 seconds...</h1>
    </body>
</html>
```

In the `WWW-Authenticate` attribute, we can see that it's value is an esoteric programming language called "Brainfuck".

**We can decode that via [an online tool](https://www.splitbrain.org/_static/ook/):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150515.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225150522.png)

- **Flag: `VU{cyberthon}`**

# Conclusion

What we've learned:

1. "Brainfuck" Esoteric Programming Language
