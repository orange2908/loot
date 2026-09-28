---
title: "Junkiness - TRX CTF 2026"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["web", "prototype-pollution", "nodejs", "junkiness", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "A small Node.js/Express 5 app with three endpoints:"
source:
  name: "CTFtime writeup #40706"
  url: "https://ctftime.org/writeup/40706"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-junkiness-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "Junkiness"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** Junkiness
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40706>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-junkiness-writeup>

---
Challenge  
A small Node.js/Express 5 app with three endpoints:

POST /register — creates a user, hardcoded isAdmin: false.  
POST /login — sets req.session.user = users[username] on success.  
GET /flag — returns the flag if req.session.user && req.session.user.isAdmin.

Vulnerability  
Two bugs in /register stack:

1\. Validation bypass via single-element array. With extended: true, username[]=__proto__ is parsed as the array ['__proto__']. The validation chain doesn't stringify first:

username.length > 8 — array length is 1. yes  
/\W/.test(['__proto__']) — the regex coerces with Array#toString, which is join(','); a 1-element array joins to just "__proto__", all word chars. yes  
Object.keys(users).includes(['__proto__']) — includes uses SameValueZero, so an array never strict-equals a string. Always false. yes  
2\. Prototype-of-users replacement. users[['__proto__']] = value keys as the string "__proto__". Writing users.__proto__ = value invokes the __proto__ setter inherited from Object.prototype, which replaces users's [[Prototype]] with value.

So the stored object becomes users's prototype — and we control that object's password field. qs happily parses password[isAdmin]=true&password[password]=x into a nested object, giving users's new prototype:  
```  
{  
username: ['__proto__'],  
password: { isAdmin: 'true', password: 'x' },  
isAdmin: false,  
}  
```
