---
title: "Ernst Echidna Web 50 - Google CTF 2016"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["ernst", "echidna", "web", "web-exploitation", "ernst-echidna-web-50", "google-ctf"]
summary: "Can you hack (url provided) website?"
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Ernst_Echidna_Web_50/README.md"
ctf:
  name: "Google CTF"
  year: 2016
  challenge: "Ernst Echidna Web 50"
---

## Source

- **CTF:** Google CTF 2016
- **Challenge:** Ernst Echidna Web 50
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Ernst_Echidna_Web_50/README.md>

---
# Ernst Echidna (Web, 50pts)

## Problem

Can you hack (url provided) website? The robots.txt sure looks interesting.

## Solution


We've got simple web page, which allows us to register an account:

![Ernst Echidna](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Ernst_Echidna_Web_50/assets/1.png)

Register form:

![Ernst Echidna](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Ernst_Echidna_Web_50/assets/2.png)

_robots.txt_ reveals one hidden path:

```
Disallow: /admin
```

At above url there's hidden administration panel and we need to has administration rights to access it.

After successful registration a cookie with MD5 hash of our login is set:

![Ernst Echidna](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Ernst_Echidna_Web_50/assets/3.png)

Simple change cookie content to MD5('admin') and refreshing browser tab allows to access panel:

![Ernst Echidna](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Ernst_Echidna_Web_50/assets/4.png)


...and reveals the flag:

![Ernst Echidna](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Ernst_Echidna_Web_50/assets/5.png)
