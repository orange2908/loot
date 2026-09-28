---
title: "sqli 7 - portswigger labs"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "web-exploitation", "sqli-7", "portswigger-labs", "siunam321"]
summary: "web writeup for \"sqli 7\" from portswigger labs - techniques: sqli, web-exploitation, sqli-7, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-7/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/SQL-Injection/sqli-7/README.md"
ctf:
  name: "portswigger labs"
  challenge: "sqli 7"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** sqli 7
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-7/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/SQL-Injection/sqli-7/README.md>

---
# SQL injection attack, querying the database type and version on Oracle | Dec 4, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle), you'll learn: SQL injection attack, querying the database type and version on Oracle! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204063239.png)

**In the previous labs, there is an SQL injection vulnerability in the product category filter:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204063335.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204063346.png)

**We found that the number of columns is 2.**

**Then, we need to find which column accepts string data type:**
```sql
' UNION ALL SELECT NULL,NULL-- -
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204063805.png)

Wait, `Internal Server Error`??

After googling a little bit, there is a StackOverflow [post](https://stackoverflow.com/questions/1881853/select-without-a-from-clause-in-oracle) talking about this:

> **Oracle database must have `FROM` clause in `SELECT` statement:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204064243.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204064308.png)

**And we can use the `dual` in-memory table exploit the SQL injection vulnerbility in the product category filter!**

**Payload:**
```sql
' UNION ALL SELECT 'a','a' FROM dual-- -
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204064502.png)

**Now, we found that all columns in the current table are accepting string data type!**

**Next, we can find the version of this Oracle database!**

**According to [PortSwigger SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), we can query the database version via:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204064809.png)

**Payload:**
```sql
' UNION ALL SELECT NULL,banner FROM v$version-- -
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-7/images/Pasted%20image%2020221204064649.png)

We found this DBMS(Database Management System) version!

# Conclusion

What we've learned:

1. SQL injection attack, querying the database type and version on Oracle
