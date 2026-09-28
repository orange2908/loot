---
title: "Secure Admin b0dee42673c6471fb8ce60696e3656b5 - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "secure", "admin", "b0dee42673c6471fb8ce60696e3656b5", "web-exploitation"]
summary: "web writeup for \"Secure Admin b0dee42673c6471fb8ce60696e3656b5\" from PeaCTF 29514edc84b44444b4806a6808a3fc68 - techniques: sqli, secure, admin, b0dee42673c6471fb8ce60696e3656b5, web-exploitation."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "Secure Admin b0dee42673c6471fb8ce60696e3656b5"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** Secure Admin b0dee42673c6471fb8ce60696e3656b5
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5.md>

---
# Secure Admin

> This is an introduction to SQL injection. If you don't know what SQLi is, we recommend checking out a tutorial here ([https://ctf101.org/web-exploitation/sql-injection/what-is-sql-injection/](https://ctf101.org/web-exploitation/sql-injection/what-is-sql-injection/)).
This admin panel seems secure?

1. Go to the link they give you
2. The challenge says we should use sql injection.. lets do that
3. Type in the following into the username text box:

    ```sql
    ' OR 1=1--
    ```

4. The site notifies us that we need an entry for both text fields

    ![Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled.png)

    - So let's enter the same thing for the password.
5. The login works

    ![Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled%201.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled%201.png)

6. The flag is peaCTF{0f8544e4-b3c2-41ae-9486-d797da048af6}
