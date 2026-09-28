---
title: "MEDICARE PHARMA - VishwaCTF 2024"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "web-exploitation", "sqli", "union-select", "command-injection", "mysql", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "We are given a web instance."
source:
  name: "CTFtime writeup #39505"
  url: "https://ctftime.org/writeup/39505"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/MediCare%20Pharma.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "MEDICARE PHARMA"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** MEDICARE PHARMA
- **Author team:** CyberCellVIIT
- **CTFtime tags:** web_exploitation
- **CTFtime:** <https://ctftime.org/writeup/39505>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/MediCare%20Pharma.pdf>

---
Solution:  
We are given a web instance. Upon visiting the instance, we find a login page for the pharmacy store.

When attempting to log in with credentials, an SQL query appears, indicating the use of MySQL as the database. This suggests that the challenge is vulnerable to SQL injection.

We attempt several standard payloads, but they don’t work. The description mentions that only authorized users can log in. This points toward using a UNION-based SQL injection payload to retrieve the credentials of authorized users.

We can enter the following payload to bypass the query and retrieve the credentials:

```  
css

`a' UNION SELECT * FROM users; -- -`  
```

Explanation:

a is set as the username.  
' closes the username field in the query.  
UNION SELECT * FROM users; retrieves all the content from the “users” database table.  
\-- - comments out the remainder of the query.

After injecting the payload, the query becomes:

```  
sql

`SELECT * FROM user WHERE username=’a’ UNION SELECT * FROM users; -- -`  
```

Executing this will return the credentials of authorized users.

Once we have the credentials, we can log in to the pharmacy. After logging in, we encounter a pharmacy store with a search bar for searching available products. However, even when searching for existing products, we receive an alert that they are not available.

Analyzing the source code, we observe that attempting to buy "Needle and Syringes" triggers a PHP file download. Part of the source code shows that input from the search bar is passed to the PHP shell_exec function, which executes system commands. This reveals that the page is vulnerable to Command Injection.

We can use this vulnerability to find the flag by running the following command:

```  
javascript

`find / -name “flag.txt” 2>/dev/null`  
```

This command searches for the file "flag.txt" and returns the result if the file is found (the 2>/dev/null part discards any errors).

Once we have the path to the flag, we use the cat command to read the flag:

```  
bash

`cat /path/to/flag.txt`  
```

Flag:

`VishwaCTF{d1g1t4l_p41n_di5p4tch3d_th4nk5_f0r_sh0pp1ng_with_M3diC4re_Ph4rm4}`
