---
title: "US TRIP-1 - VishwaCTF 2024"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "burp", "trip-1", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "From the question description, we understand that we need to find a hidden login page and bypass it to get the flag."
source:
  name: "CTFtime writeup #39504"
  url: "https://ctftime.org/writeup/39504"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/Trip%20To%20US.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "US TRIP-1"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** US TRIP-1
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39504>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/Trip%20To%20US.pdf>

---
Solution:

From the question description, we understand that we need to find a hidden login page and bypass it to get the flag. We start by clicking the hyperlink on the homepage.

Upon clicking the link, we are redirected to a page that says, “YOU ARE NOT AN IITIAN GO BACK.” By inspecting the page, we find a hint in the alt tag of the image, which says, “Change User Agent to IITIAN.”

To bypass this, we need to change the user-agent name (the name that appears while visiting the site) to “IITIAN.” There are several ways to do this, such as using a browser extension, Burp Suite, or tools like Insomnia.

In this case, I will solve it using the Google Chrome extension. First, we download the extension and add it to Chrome. Then, we create a custom user-agent by going into the settings and setting the new user-string to "IITIAN."

After changing the user-agent string to "IITIAN," we can access the login page. Here, we need to bypass the login using SQL injection.

After attempting several SQL injections on the username field, we find that it does not work. So, we try injecting SQL queries into the password field.

Let's try injecting [' or '1'='1] for the username "admin". Boom! It works! Congratulations, you have bypassed the login.

The flag is: VishwaCTF{SQL_is_Fun}
