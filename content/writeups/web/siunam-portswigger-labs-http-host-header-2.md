---
title: "http host header 2 - portswigger labs"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "http", "host", "header", "web-exploitation", "http-host-header-2"]
summary: "web writeup for \"http host header 2\" from portswigger labs - techniques: http, host, header, web-exploitation, http-host-header-2."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/HTTP-Host-Header-Attacks/http-host-header-2/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/HTTP-Host-Header-Attacks/http-host-header-2/README.md"
ctf:
  name: "portswigger labs"
  challenge: "http host header 2"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** http host header 2
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/HTTP-Host-Header-Attacks/http-host-header-2/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/HTTP-Host-Header-Attacks/http-host-header-2/README.md>

---
# Host header authentication bypass | Dec 28, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass), you'll learn: Host header authentication bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab makes an assumption about the privilege level of the user based on the HTTP Host header.

To solve the lab, access the admin panel and delete Carlos's account.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014111.png)

**Let's go to the admin panel(`/admin`):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014139.png)

it's only available to **local** users.

**In the lab's background, it said:**

> This lab makes an assumption about the privilege level of the user based on the HTTP Host header.

**Hmm... What if I intercept the GET request to `/admin`, and then modify the `Host` header to `localhost`?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014515.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014525.png)

**Let's forward that request:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014545.png)

Oh! I can access to the admin panel!

Let's delete user `carlos`!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014636.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014643.png)

Nice!

# What we've learned:

1. Host header authentication bypass
