---
title: "buckeyenotes - BuckeyeCTF 2022"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "buckeyenotes", "web-exploitation", "buckeyectf", "siunam321"]
summary: "web writeup for \"buckeyenotes\" from BuckeyeCTF - techniques: sqli, buckeyenotes, web-exploitation, buckeyectf, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/BuckeyeCTF-2022/Web/buckeyenotes/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Web/buckeyenotes/README.md"
ctf:
  name: "BuckeyeCTF"
  year: 2022
  challenge: "buckeyenotes"
---

## Source

- **CTF:** BuckeyeCTF 2022
- **Challenge:** buckeyenotes
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/BuckeyeCTF-2022/Web/buckeyenotes/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Web/buckeyenotes/README.md>

---
# buckeyenotes

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

> Note taking apps are all the rage lately but turns our they're harder to make than I thought :/. Even in development buckeyenotes has gotten some traction, Brutus signed up! I think his user name is brutusB3stNut9999. I wonder what kind of notes he writes 🤔 but I don't have his login....

[https://buckeyenotes.chall.pwnoh.io](https://buckeyenotes.chall.pwnoh.io)

> Author: rene

> Difficulty: Beginner

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210137.png)

We're prompt to a login page.

In the challenge description, **we know Brutus's username: `brutusB3stNut9999`. But we don't know his password!**

Let's test for a login attemp!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210333.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210341.png)

We got `Invalid username or password`.

Whenever I deal with login page, I always try to do a **SQL injection authenication bypass**.

**Let's try a simple `' OR 1=1-- -` payload!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210504.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210510.png)

`nice try, hacker >:D I removed your equal signs`?

Looks like there has some filtering going on.

Hmm... **What if I put that payload to the username field?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210608.png)

Logged in as `rene`. Nothing posted yet :(

Hmm... There is a username called `rene`??

I tried to use Brutus's username as rene's password, but no dice.

Let's go back to Brutus.

Armed with above information, **we need to login as `brutusB3stNut9999` via SQL injection**.

**Now, in order to bypass the `=` filter, we can just don't use `=`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105073118.png)

**Then, since we're retrieving the first record in the database, which is rene's password, we need to retrieve the second record, which is Brutus's password!**

**To do so, I'll use the `LIMIT` clause:**
```
' OR 1 LIMIT 1, 2-- -
```

This will only show 1 record in the second record.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105073328.png)

We got the flag!

# Conclusion

What we've learned:

1. SQL Injection & Bypass
