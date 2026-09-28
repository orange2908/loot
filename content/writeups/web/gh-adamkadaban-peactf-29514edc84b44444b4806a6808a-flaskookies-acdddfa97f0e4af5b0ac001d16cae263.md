---
title: "flaskookies acdddfa97f0e4af5b0ac001d16cae263 - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "flask", "flaskookies", "acdddfa97f0e4af5b0ac001d16cae263", "web-exploitation"]
summary: "web writeup for \"flaskookies acdddfa97f0e4af5b0ac001d16cae263\" from PeaCTF 29514edc84b44444b4806a6808a3fc68 - techniques: ssti, flask, flaskookies, acdddfa97f0e4af5b0ac001d16cae263, web-exploitation."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/flaskookies%20acdddfa97f0e4af5b0ac001d16cae263.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "flaskookies acdddfa97f0e4af5b0ac001d16cae263"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** flaskookies acdddfa97f0e4af5b0ac001d16cae263
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/flaskookies%20acdddfa97f0e4af5b0ac001d16cae263.md>

---
# flaskookies

> You want to log in to a really cool username generator, but there doesn't seem to be a login page. What could the website possibly use to authenticate users?

1. The problem talks about flask and cookies
    - At first I tried intercepting the cookies and decoding the session id to authenticate me, but that didn't work out.
    - Instead, let's focus on the fact that this is likely a flash app (ie. running on python)
2. When we enter in text, it outputs a variation of that to us

    ![flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled.png)

    - We can take advantage of that
3. Let's try doing some server side template injection

    ![flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled%201.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled%201.png)

    - It works! 7+9=16

    ![flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled%202.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled%202.png)

4. Let's do something a bit more useful... Maybe try to get the config info?

    ![flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled%203.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/flaskookies%20acdddfa97f0e4af5b0ac001d16cae263/Untitled%203.png)

    - This outputs the config info for the flask app
5. The flag is peaCTF{0bceec73-4b6c-42ec-957e-40f2af7971c0}
