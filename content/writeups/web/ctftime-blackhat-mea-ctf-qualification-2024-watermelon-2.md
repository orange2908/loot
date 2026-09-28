---
title: "Watermelon - BlackHat MEA CTF Qualification 2024"
category: "web"
type: "writeup"
tags: ["web", "burp", "watermelon", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "All love for Watermelons ???"
source:
  name: "CTFtime writeup #39419"
  url: "https://ctftime.org/writeup/39419"
original_source: "https://github.com/hanzalaghayasabbasi/BlackHat-MEA-2024-Qualifiers-Write-Ups/blob/main/Watermelon.md"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Watermelon"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Watermelon
- **Author team:** cyber_blitz
- **CTFtime:** <https://ctftime.org/writeup/39419>
- **Original writeup:** <https://github.com/hanzalaghayasabbasi/BlackHat-MEA-2024-Qualifiers-Write-Ups/blob/main/Watermelon.md>

---
# Watermelon Writeup

\- **Category:** Web  
\- **Points:** 120  
\- **Difficulty:** Easy

## Challenge Description

All love for Watermelons ???   
Note: The code provided is without jailing, please note that when writing exploits.

## Challenge Files

[here](<https://github.com/hanzalaghayasabbasi/BlackHat-MEA-2024-Qualifiers-Write-Ups/tree/main/Watermelon-src>)

## Steps Taken

#### 1. **Registration and Login**

I navigated to `/register` and registered a user.  
  
![image](<https://github.com/user-attachments/assets/6b80c459-419c-41dc-8287-c62f437c7a09>)

Next, I logged in using the newly created username and obtained the session cookie. I then copied the session cookie.

![image](<https://github.com/user-attachments/assets/a6802a2d-b197-482a-b340-8e8b508fb2cd>)

#### 2. **Exploration and Exploitation**

Upon analysis, I discovered that the admin password is stored in `app/[app.py](http://app.py)`. I also identified a file traversal vulnerability in the `/upload` directory.  
  
![image](<https://github.com/user-attachments/assets/bde3eb53-e89b-4c97-b309-376d940057fd>)

The files are stored in `/file/1`. Initially, Burp Suite didn't reveal much, so I used `curl` to retrieve the `[app.py](http://app.py)` file. As a result, I successfully obtained the admin password.

![image](<https://github.com/user-attachments/assets/23a06e81-05ee-45b8-ad8f-8b3978fc7528>)

As a result, I successfully obtained the admin password.

![image](<https://github.com/user-attachments/assets/b354a35e-c8ad-4a1a-8d49-dacc891046b0>)

#### 3. **Gaining Access**

I logged in with the admin credentials and copied the session cookies.

![image](<https://github.com/user-attachments/assets/16972424-73a8-41b4-9a71-1d60b60e3e48>)

#### 4. **Flag Retrieval**

Finally, I sent a GET request to `/admin`, pasted the session cookie, and successfully retrieved the flag.

![image](<https://github.com/user-attachments/assets/4acf6005-ce59-4df5-b710-f2e95fa551d9>)
