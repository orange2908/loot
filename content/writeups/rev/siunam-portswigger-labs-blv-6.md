---
title: "blv 6 - portswigger labs"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "blv", "reverse-engineering", "blv-6", "portswigger-labs", "siunam321"]
summary: "rev writeup for \"blv 6\" from portswigger labs - techniques: blv, reverse-engineering, blv-6, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-6/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-6/README.md"
ctf:
  name: "portswigger labs"
  challenge: "blv 6"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** blv 6
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-6/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Business-Logic-Vulnerabilities/blv-6/README.md>

---
# Inconsistent handling of exceptional input | Dec 20, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input), you'll learn: Inconsistent handling of exceptional input! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab doesn't adequately validate user input. You can exploit a logic flaw in its account registration process to gain access to administrative functionality. To solve the lab, access the admin panel and delete Carlos.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054542.png)

**Let's register an account:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054631.png)

In here, we see that if we work for DontWannaCry, we need to use the `dontwannacry.com` domain to register an account.

**Let's go to the `Email client`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054725.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054732.png)

- Our email address: `attacker@exploit-0ac8007404fe8d4ac00a5898012700a1.exploit-server.net`

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054807.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054817.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054826.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054836.png)

**Now we can login as user `attacker`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054900.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220054913.png)

In previous lab, we can change our email address in the `My account` page, but now we can't.

**Also, we knew that the admin panel is in `/admin`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220055140.png)

But it's only available to DontWannaCry user.

Hmm... Let's take a step back, and think what we can play with.

**In the account registration, what if the length of the email is very long?**

**Let's log out our account and register a new account:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220060341.png)

**For the email address, I'll use Metasploit's pattern create to generate long strings:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6]
└─# /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 300
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220060835.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220060912.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220060929.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220060942.png)

Hmm... The email address has been truncated...

**Let's find the length of that email address:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6]
└─# echo -n "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4" | wc -m
255
```

**Looks like the email address maximum length is 255 characters long, and the application doesn't check that when we registering!**

But how can we take advantage of that?

**What if we append the `dontwannacry.com` to the email address?**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6]
└─# echo -n "@dontwannacry.com" | wc -m
17
                                                                                                           
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6]
└─# /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 238
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8A
                                                                                                           
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6]
└─# echo -n "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8A@dontwannacry.com" | wc -m
255
                                                                                                           
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6]
└─# echo -n "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8A@dontwannacry.com.exploit-0ac8007404fe8d4ac00a5898012700a1.exploit-server.net" | wc -m
315
```

Let's do this!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220062132.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220062154.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220062204.png)

Nice! Our email address now **ends with `dontwannacry.com`!**

**Let's see can we access to the admin panel or not:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220062306.png)

**Yes we can! Let's delete user `carlos`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-6/images/Pasted%20image%2020221220062352.png)

We did it!

# What we've learned:

1. Inconsistent handling of exceptional input
