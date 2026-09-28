---
title: "Goober 2 - CTF@CIT 2026"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "mysql", "goober", "lfi", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The same box from Goober 1 still exposes SSH on 22/tcp and uftpd 2.9 on 10921/tcp."
source:
  name: "CTFtime writeup #40739"
  url: "https://ctftime.org/writeup/40739"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Goober 2"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Goober 2
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40739>

---
# Goober 2 — Writeup

\- Category: Fullpwn  
\- Value: 941  
\- Author: bootstrap

## Challenge

> Find flag2. Good luck!  
>  
> `23.179.17.69`  
>  
> Hint: There is no traditional 'root' flag. Look for it elsewhere.

## Recon

The same box from `Goober 1` still exposes SSH on `22/tcp` and `uftpd 2.9` on `10921/tcp`.

Anonymous FTP works, and `uftpd 2.9` is vulnerable to path traversal through `RETR`, so fetching `../../home/jimbo/.bash_history` reveals `jimbo`'s password:

```text  
mysql -u jimbo -pADFwPAcHDNCSGoyCwik6  
```

## Solve

SSH in as `jimbo` with that password and list the home directory. The challenge hint is literal: there is no root-only flag to recover. `flag2.txt` sits directly in `jimbo`'s home and is readable by `jimbo`.

```text  
/home/jimbo/flag2.txt  
```

Reading the file gives the challenge flag:

```text  
CIT{Br41n_bLa$t3R}  
```

## Flag

```text  
CIT{Br41n_bLa$t3R}  
```

## Files

\- [scripts/[solve.py](http://solve.py)](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/41-goober-2/scripts/[solve.py](http://solve.py))  
\- [solution/flag.txt](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/41-goober-2/solution/flag.txt)  
\- [other/fetched/jimbo-bash-history-snippet.txt](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/41-goober-2/other/fetched/jimbo-bash-history-snippet.txt)  
\- [other/fetched/jimbo-home-listing.txt](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/41-goober-2/other/fetched/jimbo-home-listing.txt)  
\- [other/fetched/flag2.txt](/Users/bytedance/Documents/CTF/CIT%202026/Fullpwn/41-goober-2/other/fetched/flag2.txt)
