---
title: "ac 9 - portswigger labs"
category: "web"
subcategory: "idor"
type: "writeup"
tags: ["web", "burp", "idor", "web-exploitation", "ac-9", "portswigger-labs"]
summary: "web writeup for \"ac 9\" from portswigger labs - techniques: burp, idor, web-exploitation, ac-9, portswigger-labs."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-9/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-9/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 9"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 9
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-9/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-9/README.md>

---
# Insecure direct object references | Dec 14, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references), you'll learn: Insecure direct object references! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

Solve the lab by finding the password for the user `carlos`, and logging into their account.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015541.png)

**In here, we can see there is a `Live chat` link:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015714.png)

**Hmm... Let's send something and intercept the request in Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015805.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015842.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015944.png)

Nothing weird. **How about the `View transcript` button?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020031.png)

It's sending a POST request to `/download-transcript` with the `transcript` data.

Let's forward that request.

**Then, we'll see this request, which is very interesting:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020213.png)

**It's sending a GET request to `/download-transcript/4.txt`!**

**Hmm... What if I change the `4.txt` to `1.txt`? Or `2.txt`, and so on?**

**To do so, I'll send that GET request to Burp Suite's Repeater and hit `Send`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020342.png)

Now, we can see our own session's transcript.

**How about I change it to `1.txt`?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020454.png)

**As you can see, we saw the first transcript in this live chat, and also someone's password! I'm guessing it's user `carlos`'s password!**

**Let's login as user `carlos`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020640.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020650.png)

I'm in!

# What we've learned:

1. Insecure direct object references
