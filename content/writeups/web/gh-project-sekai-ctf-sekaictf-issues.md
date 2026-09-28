---
title: "issues - sekaictf 2022"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "jwt", "open-redirect", "issues", "web-exploitation", "sekaictf"]
summary: "web writeup for \"issues\" from sekaictf - techniques: jwt, open-redirect, issues, web-exploitation, sekaictf."
source:
  name: "project-sekai-ctf/sekaictf-2022"
  url: "https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/web/issues/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2022
  challenge: "issues"
---

## Source

- **CTF:** sekaictf 2022
- **Challenge:** issues
- **Repository:** [project-sekai-ctf/sekaictf-2022](https://github.com/project-sekai-ctf/sekaictf-2022)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/web/issues/solution/README.md>

---
# Writeup

1. Notice open redirect at `/logout` endpoint. `http://issues.com/logout?redirect=http://whatever.com`

2. Notice that in authorization for /api routes, the issuer in the jwt isn't properly validated. Only the hostname/netloc part of the issuer url is validated. i.e authorization expects something like `http://localhost:8080/jwks.json` but since only `localhost:8080` is validated, `http://localhost:8080/logout?redirect=http://whatever.com?` is a valid issuer as well.

3. Notice that by combining issuer validation bug with open redirect, we can craft an issuer that will pass the validation but redirect to a server we control, allowing us to supply our own version of jwks.json that will then be used for signature verification.

`http://localhost:8080/logout?redirect=http://165.232.137.131:8000/fake_jwks.json?`

4. Create publicly reachable jwks.json containing public key for signature verification.

5. Sign jwt with payload `{"user":"admin"}` with private key that corresponds to pub key in our jwks.json.

6. Use this jwt to access the `/api/flag` endpoint to get the flag.
