---
title: "sqli 8 - portswigger labs"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "mysql", "web-exploitation", "sqli-8"]
summary: "web writeup for \"sqli 8\" from portswigger labs - techniques: sqli, union-select, mysql, web-exploitation, sqli-8."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-8/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/SQL-Injection/sqli-8/README.md"
ctf:
  name: "portswigger labs"
  challenge: "sqli 8"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** sqli 8
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-8/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/SQL-Injection/sqli-8/README.md>

---
# SQL injection attack, querying the database type and version on MySQL and Microsoft | Dec 5, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft), you'll learn: SQL injection attack, querying the database type and version on MySQL and Microsoft! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205054653.png)

**In the previous labs, we found that there is an SQL injection vulnerability in the product category filter:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205054946.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205055007.png)

And we found that **there are 2 columns in this table.**

**To find the database version, we need to:**

- Find out which column accepts string data type:

```sql
' UNION SELECT 'string1','string2'-- -
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205055111.png)

Both are accepting string data type.

- List the DBMS(Database Management System) version via `version()`:

```sql
' UNION SELECT NULL,version()-- -
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205055228.png)

# What we've learned:

1. SQL injection attack, querying the database type and version on MySQL and Microsoft
