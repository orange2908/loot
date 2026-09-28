---
title: "get flag 2 - Incognito 4 0"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "web-exploitation", "get-flag-2", "incognito-4-0", "siunam321"]
summary: "So this challenge is almost the same as the \"get flag 1\" challenge, which is a SSRF localhost filter bypass."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/Incognito-4.0/Web/get-flag-2/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Incognito-4.0/Web/get-flag-2/README.md"
ctf:
  name: "Incognito 4 0"
  challenge: "get flag 2"
---

## Source

- **CTF:** Incognito 4 0
- **Challenge:** get flag 2
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/Incognito-4.0/Web/get-flag-2/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Incognito-4.0/Web/get-flag-2/README.md>

---
# get flag 2

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217202938.png)

## Enumeration

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217202948.png)

So this challenge is almost the same as the "get flag 1" challenge, which is a **SSRF localhost filter bypass**.

**When we clicked the "Submit" button, it'll send a GET request to `/getUrl`, with parameter `url`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217203113.png)

**In "get flag 1", we used the following payload to bypass the localhost filter:**
```
http://127.1:9001/flag.txt
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217203209.png)

However, it won't work in this challenge.

**Again, refer to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#localhost):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217203327.png)

**After some trial and error, this bypass works:**
```
http://[::]:9001/flag.txt
```

If I recall correctly, the `[::]` is the representation of IPv6's localhost.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217203400.png)

We got the flag!

- **Flag: `ictf{ch3ck_1p_v6_cr239eatf21}`**

# Conclusion

What we've learned:

1. Exploiting SSRF (Server-Side Request Forgery) & Bypassing Filters Via IPv6 IP Address
