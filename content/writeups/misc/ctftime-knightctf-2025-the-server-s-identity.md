---
title: "The Server's Identity - KnightCTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "server", "identity", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "Find the hostname of the server."
source:
  name: "CTFtime writeup #39816"
  url: "https://ctftime.org/writeup/39816"
original_source: "https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/The_Server&#39;s_Identity.md"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "The Server's Identity"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** The Server's Identity
- **Author team:** Not_So_Intelligent
- **CTFtime:** <https://ctftime.org/writeup/39816>
- **Original writeup:** <https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/The_Server&#39;s_Identity.md>

---
## The Server's Identity

Find the **hostname** of the server.

## Steps

Use the `strings` command and `grep` to find the keyword `localhost` and `hostname`

```bash  
strings capture2.pcapng | grep -i "localhost" | grep -i "hostname"  
```

We will get something like this:

```bash  
var environment = {"is_cockpit_client":false,"page":{"connect":true,"require_host":false,"allow_multihost":true},"logged_into":[],"hostname":"localhost.localdomain","os-release":{"NAME":"Rocky Linux","ID":"rocky","PRETTY_NAME":"Rocky Linux 9.5 (Blue Onyx)","CPE_NAME":"cpe:/o:rocky:rocky:9::baseos","ID_LIKE":"rhel centos fedora"},"CACertUrl":"/ca.cer"};  
"Hostname": "localhost",  
"DefaultHostname": "localhost",  
"Hostname": "localhost",  
"DefaultHostname": "localhost",

```

We can see that the host name is:

```bash  
"hostname": "localhost.localdomain"  
```

Hence, the falg is:

```bash  
KCTF{localhost.localdomain}  
```
