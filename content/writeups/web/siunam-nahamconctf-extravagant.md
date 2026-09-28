---
title: "EXtravagant - nahamconctf 2022"
category: "web"
subcategory: "xxe"
type: "writeup"
tags: ["web", "xxe", "file-upload", "reverse-shell", "extravagant", "web-exploitation"]
summary: "In this challenge, you'll learn more about XXE(XML external entity injection)."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/nahamconctf2022/Web/EXtravagant/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/Web/EXtravagant/README.md"
ctf:
  name: "nahamconctf"
  year: 2022
  challenge: "EXtravagant"
---

## Source

- **CTF:** nahamconctf 2022
- **Challenge:** EXtravagant
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/nahamconctf2022/Web/EXtravagant/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/Web/EXtravagant/README.md>

---
# Background
![background](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Web/EXtravagant/images/background.png)

In this challenge, you'll learn more about `XXE(XML external entity injection)`. As usual, let's start the instance via the Start button on the top-right, and browse the website.

![soltion1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Web/EXtravagant/images/solution1.png)

In the `about` page, we can see the site is using `XML parsing`, and we can upload a sample in `Trial` page, and view it on the `View XML` page. Hmm... Maybe we can do a `XXE, or XML external entity injection`?? Next, I started to google `XXE file upload exploit`, and I found one PDF explaining that exploit in **[exploit-db](https://www.exploit-db.com/docs/49732)**. It said:

> **"If the application allows user to upload svg files on the system, then the XXE can be exploited using them, and a SVG file is to define graphics in XML format."**

Then I found a **XXE inside SVG upload payload** at [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md).

Let's copy and paste it to our text editor. Also, **According to the background of this challenge, the flag is in /var/www**, so let's modify the path from "file:///etc/hostname" to `"file:///var/www/flag.txt"`, and save it as a SVG file.

![soltion2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Web/EXtravagant/images/solution2.png)

Now, upload the SVG payload to `Trial` page.

![soltion3](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Web/EXtravagant/images/solution3.png)

![soltion4](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Web/EXtravagant/images/solution4.png)

Upload successful!! Let's go to the `View XML` page to see is it work!

![soltion5](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Web/EXtravagant/images/solution5.png)

![flag](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Web/EXtravagant/images/flag.png)

Yes!! We've the flag!


# Trivia

Before I realized it's a XXE, I've tried to upload a php reverse shell, but it doesn't work. Lol
