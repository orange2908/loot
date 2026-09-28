---
title: "Wingstop 1 - CTF@CIT 2026"
category: "web"
type: "writeup"
tags: ["web", "nmap", "wingstop", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The target exposes Wing FTP Server over both HTTP and FTP."
source:
  name: "CTFtime writeup #40738"
  url: "https://ctftime.org/writeup/40738"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Wingstop 1"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Wingstop 1
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40738>

---
# Wingstop 1 — Writeup

\- Category: Fullpwn  
\- Value: 996  
\- Author: bootstrap

## Challenge

> Find flag1. Good luck!  
>  
> `23.179.17.68`

## Recon

The target exposes Wing FTP Server over both HTTP and FTP.

```text  
21/tcp open ftp  
80/tcp open http  
3300/tcp open ceph  
5985/tcp open wsman  
```

The web root immediately identifies the service:

```text  
Server: Wing FTP Server(UNREGISTERED)  
```

Anonymous FTP is enabled and exposes a single file, `backup.xml`. That file contains the Wing FTP admin backup with an MD5 password hash:

```xml  
<ADMIN>  
<Admin_Name>Admin</Admin_Name>  
<Password>44ffe44097bbce02fbaa42734e92ae04</Password>  
</ADMIN>  
```

That hash is `Password@1`, but the real win is that the target is also vulnerable to `CVE-2025-47812`, the unauthenticated Wing FTP `loginok.html` null-byte/Lua injection bug.

## Solve

Use the web interface bug to inject a small Lua snippet into the session file via the `username` field. The snippet runs:

```text  
type C:\\\Users\\\bob\\\Desktop\\\flag1.txt  
```

Then request `dir.html` with the returned `UID` cookie. Wing FTP executes the poisoned session file and prints the command output before the normal XML response body, leaking the flag.

The important part is doubling the backslashes in the Windows path so the injected Lua string survives correctly.

## Flag

```text  
CIT{p1Gs_0n_tH3_W1ng}  
```

## Files

\- [scripts/[solve.py](http://solve.py)](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/37-wingstop-1/scripts/[solve.py](http://solve.py))  
\- [solution/flag.txt](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/37-wingstop-1/solution/flag.txt)  
\- [other/fetched/backup.xml](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/37-wingstop-1/other/fetched/backup.xml)  
\- [other/fetched/nmap.txt](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/37-wingstop-1/other/fetched/nmap.txt)
