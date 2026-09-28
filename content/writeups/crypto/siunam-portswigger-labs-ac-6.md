---
title: "ac 6 - portswigger labs"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "wiener", "privesc", "rsa", "cryptography", "ac-6"]
summary: "crypto writeup for \"ac 6\" from portswigger labs - techniques: wiener, privesc, rsa, cryptography, ac-6."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-6/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-6/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ac 6"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ac 6
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-6/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Access-Control/ac-6/README.md>

---
# User ID controlled by request parameter, with unpredictable user IDs | Dec 14, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids), you'll learn: User ID controlled by request parameter, with unpredictable user IDs! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

To solve the lab, find the GUID for `carlos`, then submit his API key as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-6/images/Pasted%20image%2020221214011714.png)

**Login as user `wiener`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-6/images/Pasted%20image%2020221214011742.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-6/images/Pasted%20image%2020221214011749.png)

**In the previous lab, we found that the `My account` link is supplying an `id` GET parameter, let's view the source again:**
```html
[...]
<section class="top-links">
    <a href=/>Home</a><p>|</p>
    <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/my-account?id=55b2eb8a-6a18-40f9-bd35-7c04b4939bae">My account</a><p>|</p>
    <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/logout">Log out</a><p>|</p>
</section>
[...]
```

**This time, it's using an GUID(Globally Unique Identifier).**

Hmm... It seems like we couldn't guess another user...

**Let's explore this site:**

**In the home page, we can view other people's posts:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-6/images/Pasted%20image%2020221214012431.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-6/images/Pasted%20image%2020221214012445.png)

And you can see, it includes the author's name!

**Let's view the source again:**
```html
<p><span id=blog-author><a href='https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/blogs?userId=2603c122-a7b8-4bda-b0eb-780b8fbc5016'>carlos</a></span> | 16 November 2022</p>
```

**Oh! We found `carlos` GUID: `2603c122-a7b8-4bda-b0eb-780b8fbc5016`!!**

**Now we can use his GUID to see his API key in the `My account` link!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Access-Control/AC-6/images/Pasted%20image%2020221214012656.png)

We're user `carlos` and found his API key!

# What we've learned:

1. User ID controlled by request parameter, with unpredictable user IDs
