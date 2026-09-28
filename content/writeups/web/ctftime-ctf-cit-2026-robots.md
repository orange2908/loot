---
title: "Robots - CTF@CIT 2026"
category: "web"
type: "writeup"
tags: ["web", "robots", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Flag: CIT{S8kMc789Gd37Py1gQPiWbeqxx}"
source:
  name: "CTFtime writeup #40727"
  url: "https://ctftime.org/writeup/40727"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Robots"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Robots
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40727>

---
# Robots — Writeup

\- **Category:** Misc  
\- **Points:** 877  
\- **Flag:** `CIT{S8kMc789Gd37Py1gQPiWbeqxx}`

## Observations

\- No attachments, description is just "Beep Boop".  
\- Challenge title "Robots" → classic pointer to `robots.txt`, the file  
web crawlers read to learn which paths to skip.

## Solution

Fetch the site's `robots.txt`:

```sh  
curl -sS https://ctf.cyber-cit.club/robots.txt  
```

The file looks innocuous:

```text  
User-agent: *  
Disallow: /admin  
```

…but `Content-Length: 1047` is much bigger than those two lines. The body  
is padded with ~300 blank lines, and the flag is printed at the very  
bottom — easy to miss unless you scroll (or use `tail`):

```sh  
curl -sS https://ctf.cyber-cit.club/robots.txt | tail -n 1  
# -> CIT{S8kMc789Gd37Py1gQPiWbeqxx}  
```

## Red herring

\- `Disallow: /admin` is a misdirection. `/admin` exists but just 302-redirects  
to `/login` (standard CTFd). The flag is in the file itself, not behind  
the disallowed path.

## Reproduce

```sh  
bash scripts/[solve.sh](http://solve.sh)  
```
