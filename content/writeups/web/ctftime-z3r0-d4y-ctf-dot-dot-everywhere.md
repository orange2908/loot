---
title: "dot dot everywhere - Z3R0 D4Y CTF"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "jwt", "stegsolve", "dot", "everywhere", "z3r0-d4y-ctf", "ctf-writeup"]
summary: "Description: One of the admins is an undercover agent."
source:
  name: "CTFtime writeup #39585"
  url: "https://ctftime.org/writeup/39585"
original_source: "https://github.com/BogusForlorn/CTF_Writeups/blob/main/Z3R0%20D4Y%20CTF/Forensics/dot%20dot%20everywhere.md"
ctf:
  name: "Z3R0 D4Y CTF"
  challenge: "dot dot everywhere"
---

## Metadata

- **CTF:** Z3R0 D4Y CTF
- **Task:** dot dot everywhere
- **Author team:** C0UGH1NGB4BY
- **CTFtime:** <https://ctftime.org/writeup/39585>
- **Original writeup:** <https://github.com/BogusForlorn/CTF_Writeups/blob/main/Z3R0%20D4Y%20CTF/Forensics/dot%20dot%20everywhere.md>

---
Description: One of the admins is an undercover agent. she sent a mysterious file in our group just before deleting her number. Can you help us to decipher what this file is about!

The challenge gives us a GIF file. At first glance, this doesn't look like much. But upon closer inspection, we can actually see that each frame corresponds to the one before. Every 6 frames make a row. My initial idea was to use stegsolve's frame browser and extract every frame, then putting them all together on MS paint. But as I got to frame 50, I noticed that the last frame was much bigger in size and dimensions because it actually holds the combined frames. I didn't have to do all that hard work.

![](<https://private-user-images.githubusercontent.com/136268503/380565520-be7087c5-ca34-45b7-a959-7eac0c70e5d7.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjYzOTgsIm5iZiI6MTczMDE2NjA5OCwicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTY1NTIwLWJlNzA4N2M1LWNhMzQtNDViNy1hOTU5LTdlYWMwYzcwZTVkNy5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTQxMzhaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT05MzI5NGYyZmU5NDljNzM0ZTk5ODQwZTIxMmRmNTE4NjNkOTMzNjg1NzhjYzExZjNhMzZiZWRkN2M5MWY3ZDY2JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.s1KBPeW0ycjitGiwxj7E5cL9rR-KXoBcSCjX_xrj3wk>)

I got this dot image, but I didn't know what it first. So I reverse google imaged to see what I can learn about it. Google tells that it is a DotCode. And so, using an online DotCode decoder, I got the flag.

![](<https://private-user-images.githubusercontent.com/136268503/380565690-60854877-aad6-4f78-b0e0-9e37f6c69f24.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjYzOTgsIm5iZiI6MTczMDE2NjA5OCwicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTY1NjkwLTYwODU0ODc3LWFhZDYtNGY3OC1iMGUwLTllMzdmNmM2OWYyNC5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTQxMzhaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1jYjRiYzY2NTc2MzU1ZGUxYTljMDIyMDdlMzQxZDQyODlkNjYwYjM0MWM0OWQwOWY5OTEyZDVhZDUzNjIyMmJlJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.4pPKJbFsVoweUBBBAm2-qsIqxf6J0589Gv7ooZrXaTk>)
