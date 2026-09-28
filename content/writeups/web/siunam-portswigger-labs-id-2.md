---
title: "id 2 - portswigger labs"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "cgi", "web-exploitation", "id-2", "portswigger-labs", "siunam321"]
summary: "web writeup for \"id 2\" from portswigger labs - techniques: cgi, web-exploitation, id-2, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Information-Disclosure/id-2/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Information-Disclosure/id-2/README.md"
ctf:
  name: "portswigger labs"
  challenge: "id 2"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** id 2
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Information-Disclosure/id-2/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Information-Disclosure/id-2/README.md>

---
# Information disclosure on debug page | Dec 16, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page), you'll learn: Information disclosure in error messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the `SECRET_KEY` environment variable.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-2/images/Pasted%20image%2020221216052826.png)

**Let's view the source page!**
```html
	</div>
</section>
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
```

**Oh look! We found an interesting HTML comment tag! Which is an `<a>` tag that pointing to PHP info page!**

**Let's go there:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-2/images/Pasted%20image%2020221216053016.png)

**In the `Environment` session, we found a `SECRET_KEY`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Information-Disclosure/ID-2/images/Pasted%20image%2020221216053033.png)

# What we've learned:

1. Information disclosure on debug page
