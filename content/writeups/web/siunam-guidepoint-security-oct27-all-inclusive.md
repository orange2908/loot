---
title: "All-Inclusive - GuidePoint-Security-Oct27 2022"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "lfi", "gobuster", "base64", "all-inclusive", "web-exploitation"]
summary: "In this challenge, we can start a docker instance:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/All-Inclusive/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/All-Inclusive/README.md"
ctf:
  name: "GuidePoint-Security-Oct27"
  year: 2022
  challenge: "All-Inclusive"
---

## Source

- **CTF:** GuidePoint-Security-Oct27 2022
- **Challenge:** All-Inclusive
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/All-Inclusive/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/All-Inclusive/README.md>

---
# All Inclusive

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can start a docker instance:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083233.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083315.png)

**View-Source:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083335.png)

**Hmm... We're missing a GET parameter: `SPOT`? Let's provide that in the `index.php`.**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083851.png)

**Oh! We can include files!**

**Let's use base64 PHP wrapper to find the source code of `index.php`!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027085202.png)

**Copy and decode that:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/All-Inclusive]
└─# subl index.b64

┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/All-Inclusive]
└─# cat index.b64 | base64 -d > index.php
```

**`index.php`:**
```php
<?php
$flag = 'Null';
if ( $null != "$_GET[SPOT]" ) {
	include("$_GET[SPOT]");
}
else {
	echo "<!-- Missing GET parameter SPOT -->";
}
?>
```

Nothing weird in here...

**Hmm... Let's enumerat hidden PHP file via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/All-Inclusive]
└─# gobuster dir -u http://10.10.100.200:59529/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php
[...]
/flag.php             (Status: 403) [Size: 281]
[...]
```

**Found `flag.php`!!**

**Let's use that Local File Inclusion (LFI) vulnerablilty to get the flag!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027085533.png)

# Conclusion

What we've learned:

1. Exploiting Local File Inclusion (LFI)
