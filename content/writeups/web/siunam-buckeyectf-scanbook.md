---
title: "scanbook - BuckeyeCTF 2022"
category: "web"
subcategory: "image"
type: "writeup"
tags: ["web", "qr-code", "idor", "scanbook", "image", "web-exploitation"]
difficulty: "easy"
summary: "web writeup for \"scanbook\" from BuckeyeCTF - techniques: qr-code, idor, scanbook, image, web-exploitation."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/BuckeyeCTF-2022/Web/scanbook/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Web/scanbook/README.md"
ctf:
  name: "BuckeyeCTF"
  year: 2022
  challenge: "scanbook"
---

## Source

- **CTF:** BuckeyeCTF 2022
- **Challenge:** scanbook
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/BuckeyeCTF-2022/Web/scanbook/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Web/scanbook/README.md>

---
# scanbook

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

> Tickets, please.

[https://scanbook.chall.pwnoh.io](https://scanbook.chall.pwnoh.io)

> Author: gsemaj

> Difficulty: Easy

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105020458.png)

Let's test what the website is doing!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105020714.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105020733.png)

**After I submitted a content, I'll be prompt to a page to scan/download the QR code.**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105020756.png)

**Also, the QR code picture might vulnerable to IDOR (Insecure Direct Object References)!**

How about we upload that ticket?

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105021333.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105021407.png)

Hmm... **How about I upload others ticket, and read it??**

**Let's say `41340811.png`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105073648.png)

**Download it and upload it:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105073708.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105073714.png)

Hmm...

I'm also curious about what the QR has. Let's use an [online QR code reader](https://products.aspose.app/barcode/recognize/qr):

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105075740.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/scanbook]
└─# ls -lah /home/nam/Downloads 
total 16K
drwxr-xr-x  2 nam nam 4.0K Nov  5 07:55 .
drwxr-xr-x 30 nam nam 4.0K Nov  4 20:54 ..
-rw-r--r--  1 nam nam  665 Nov  5 07:51 41340867.png
```

**It's reading the plaintext content based on the filename??**

**How about we generate a QR code that contains the filename on the web server??**

**To do so, I'll use an [online QR code generator](https://products.aspose.app/barcode/generate):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105075942.png)

**Let's try to find the first one (`1`) uploaded plaintext!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105075953.png)

Upload it:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105080055.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105080104.png)

`Sorry, we lost your post.`?? **Maybe `1.png` doesn't exist?**

**Let's try `0` then:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105080155.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105080206.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105080220.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105080230.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105080241.png)

Boom! We got the flag!

# Conclusion

What we've learned:

1. IDOR (Insecure Direct Object References)
