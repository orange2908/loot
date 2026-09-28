---
title: "Migration - sstf samsung 2020"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "migration", "web-exploitation", "sstf-samsung", "perfectblue"]
summary: "In this challenge we are given two sites at :5555 and :7777."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/sstf-samsung-2020/Migration/README.md"
ctf:
  name: "sstf samsung"
  year: 2020
  challenge: "Migration"
---

## Source

- **CTF:** sstf samsung 2020
- **Challenge:** Migration
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/sstf-samsung-2020/Migration/README.md>

---
Migration
=========

In this challenge we are given two sites at :5555 and :7777.

On the 5555 site, we can login with a user/password and we get access to a migrate.php page.
On this page, we can enter a new user_id and password.

On the 7777 site, we can enter this new user_id and password to login.

There is a SQL injection on the INSERT statement, so we can use this to leak data.

The way we do this is by leaking byte-by-byte. To leak one byte of data, we hash it and use it as password for the new account.
Then on the 7777 site, we bruteforce the password on the new site to find out which byte it was.

As there is a delay of about 1 minute between the reset of the database on the new site, we have to cycle between accounts as we can only
migrate an account once.

The script to get output from arbitrary SQL queries can be found in `brute.py`. We can use this to dump all the tables and columns, and then
get the flag.
