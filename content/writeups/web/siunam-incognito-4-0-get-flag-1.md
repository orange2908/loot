---
title: "get flag 1 - Incognito 4 0"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "web-exploitation", "get-flag-1", "incognito-4-0", "siunam321"]
summary: "As you can see, it's a simple HTML form."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/Incognito-4.0/Web/get-flag-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Incognito-4.0/Web/get-flag-1/README.md"
ctf:
  name: "Incognito 4 0"
  challenge: "get flag 1"
---

## Source

- **CTF:** Incognito 4 0
- **Challenge:** get flag 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/Incognito-4.0/Web/get-flag-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Incognito-4.0/Web/get-flag-1/README.md>

---
# get flag 1

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217201529.png)

## Enumeration

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217201547.png)

**View source page:**
```html
[...]
<h1>URL Form</h1>
<form action="/getUrl" method="get">
    <div class="form-group">
        <label for="url">Enter URL:</label>
        <input type="text" class="form-control" id="url" name="url" placeholder="Enter URL here" required>
    </div>
    <button type="submit" class="btn btn-primary">Submit</button>
</form>
[...]
```

As you can see, it's a simple HTML form.

When we clicked the "Submit" button, it'll send a GET request to `/getUrl`, with parameter `url`.

**Let's try to send something:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217201737.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217201758.png)

In here, our supplied URL is reflected to the web page!

## Exploitation

Armed with above information, it seems like it may be vulnerable to SSRF (Server-Side Request Forgery)! Which means **we can try to reach internal services**!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217202633.png)

Umm... What??

It should reach to the internal service on port 9001...

Maybe there are some filters??

If so, we can try to bypass that.

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#localhost), we can use the following payload to bypass it:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217202749.png)

**After some trial and error, this payload works!**
```
http://127.1:9001/flag.txt
```

This payload `127.1` is the same as `127.0.0.1`, which is localhost.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Incognito-4.0/images/Pasted%20image%2020230217202823.png)

Nice! We got the flag!

- **Flag: `ictf{l0c4l_byp4$$_323theu0a9}`**

# Conclusion

What we've learned:

1. Exploiting SSRF (Server-Side Request Forgery) & Bypassing Filters
