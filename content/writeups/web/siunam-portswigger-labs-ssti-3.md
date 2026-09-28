---
title: "ssti 3 - portswigger labs"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "web-exploitation", "ssti-3", "portswigger-labs", "siunam321"]
summary: "web writeup for \"ssti 3\" from portswigger labs - techniques: ssti, web-exploitation, ssti-3, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Server-Side-Template-Injection/ssti-3/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Server-Side-Template-Injection/ssti-3/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ssti 3"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ssti 3
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Server-Side-Template-Injection/ssti-3/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Server-Side-Template-Injection/ssti-3/README.md>

---
# Server-side template injection using documentation | Dec 23, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation), you'll learn: Server-side template injection using documentation! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection). To solve the lab, identify the template engine and use the documentation to work out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials:

`content-manager:C0nt3ntM4n4g3r`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035728.png)

**Login as user `content-manager`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035758.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035806.png)

First, we need to **detect** is there any Server-Side Template Injection(SSTI) vulnerability in this web application.

**After poking around this site, I found that we can edit product posts:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035947.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040007.png)

As you can see, it allows us to edit product posts' template!

**Let's clean that up and figure out which template engine is using:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040112.png)

**Let's trigger an error:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040136.png)

As you can see, **this web application is using FreeMarker template engine, which is written in Java.**

Let's find out how to get code execution!

**In the [FreeMarker documentation](https://freemarker.apache.org/docs/api/freemarker/template/utility/Execute.html), we can execute OS command via this:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040729.png)

Let's try it!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040829.png)

**However, it won't work. Because the server doesn't have this setting:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040903.png)

**After some googling, this [blog](https://ackcent.com/in-depth-freemarker-template-injection/) helps us:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040939.png)

We can use the template engine to enable the OS command execution!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223041110.png)

Boom! We got code execution!

Let's delete `morale.txt` file!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223041205.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223041221.png)

We did it!

# What we've learned:

1. Server-side template injection using documentation
