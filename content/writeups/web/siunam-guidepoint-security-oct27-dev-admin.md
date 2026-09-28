---
title: "Dev-Admin - GuidePoint-Security-Oct27 2022"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "base64", "dev-admin", "web-exploitation", "guidepoint-security-oct27", "siunam321"]
summary: "In this challenge, we can spawn a docker instance:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin/README.md"
ctf:
  name: "GuidePoint-Security-Oct27"
  year: 2022
  challenge: "Dev-Admin"
---

## Source

- **CTF:** GuidePoint-Security-Oct27 2022
- **Challenge:** Dev-Admin
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin/README.md>

---
# Dev Admin

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can spawn a docker instance:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029003813.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029003849.png)

The reason why it said `Not Authorized!`, is becase **when we go to this page (`index.php`), it sets a cookie for us**!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004110.png)

**We have a cookie is set, and the key name called `dev_session`!**

**The `%3D` is URL encoded, let's decode that:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004213.png)

**It's a base64 encoded string! Let's decode that via `base64 -d`!**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin]
└─# echo "YWRtaW5pc3RyYXRvcjpmYWxzZQ==" | base64 -d
administrator:false
```

**Nice! What if we set the `false` value to `true`?? Will I become authorized?**

**To do so, I'll reverse the above processes:** (`-n` for no new line character)
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin]
└─# echo -n "administrator:true" | base64          
YWRtaW5pc3RyYXRvcjp0cnVl
```

**Edit the cookie:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004424.png)

**Then hard refresh the page: (`Ctrl + Shift + R`)**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004450.png)

We got the flag!

# Conclusion

What we've learned:

1. Authentication Bypass via Weak Cookie Value
