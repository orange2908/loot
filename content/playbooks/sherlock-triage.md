---
title: "Playbook - HTB Sherlock (Blue Team DFIR) Triage"
category: sherlocks
subcategory: triage
type: playbook
tags: [sherlock, sherlocks, htb, hackthebox, blue-team, dfir, incident-response, evtx, pcap, timeline, windows-event-logs, active-directory, where-to-start, hacktheblue, triage, kape, mft, usnjrnl]
summary: "Start-to-finish flow for an HTB Sherlock: pull it, unzip with hacktheblue, map hosts, convert evtx to JSONL, build a process timeline, correlate with the pcap, answer in the exact mask format."
when_to_use:
  - "You started a Hack The Box Sherlock (DFIR / blue team) and have a zip of triage artifacts"
  - "The evidence is a KAPE-style C/ tree (Windows/System32/winevt/Logs, $MFT, $J) plus maybe a pcap"
  - "Questions ask for timestamps, IPs, command lines, accounts or logon GUIDs"
  - "You are stuck on a timestamp answer that looks right but HTB says incorrect"
related: [windows-evtx-hunting, ad-attack-detection-event-ids, pcap-dfir-tshark, evtx-to-jsonl-timeline, htb-sherlock-api-submit, htb-mcp-sherlocks, htb-sasync]
---

## TL;DR

1. Pull: `sherlock_tasks` + `sherlock_download` (htb-mcp), or the raw API (`ctfbrain show scripts:sherlocks:htb-sherlock-api-submit`).
2. Unzip: **the password is always `hacktheblue`** (challenges use `hackthebox`). `7z x -phacktheblue X.zip`
3. Read **every task first**. The masks leak the answer shape (`.\XxxxxXxxxxx.xxx --xxxxxxxx ...` tells you the tool name length).
4. Convert all `.evtx` to JSONL once, then grep and jq across it (`evtx-to-jsonl-timeline`).
5. Build the process timeline from Security 4688 (and Sysmon 1 if present) and read it top to bottom.
6. Correlate with the pcap. **The pcap and host clocks can differ by seconds.** If a log timestamp is rejected, try the packet time.
7. Submit one answer, confirm the endpoint works, then submit slowly. HTB rate-limits (`Too Many Attempts.`).

## 1. Pull and unpack

```sh
# the htb-mcp token lives here; never print it
T=$(cat ~/.config/htb-mcp/token)
# find the id
curl -s -H "Authorization: Bearer $T" "https://labs.hackthebox.com/api/v4/sherlocks?keyword=SaSync" | jq '.data[] | {id,name,difficulty}'
# list tasks with masks
curl -s -H "Authorization: Bearer $T" https://labs.hackthebox.com/api/v4/sherlocks/1692/tasks | jq -r '.data[] | "\(.id)\t\(.masked_flag)\t\(.description)"'
# download (signed link, 1h validity)
U=$(curl -s -H "Authorization: Bearer $T" https://labs.hackthebox.com/api/v4/sherlocks/1692/download_link | jq -r .url)
curl -sL -o sherlock.zip "$U"
# the Sherlock password
7z x -y -phacktheblue sherlock.zip
# test first if unsure
7z t -phacktheblue sherlock.zip | tail -3
```

## 2. Map the evidence

```sh
# hosts are usually top-level dirs: <HOST>/C/...
find . -maxdepth 3 -type d
# biggest logs usually hold the story
ls -laS */C/Windows/System32/winevt/Logs 2>/dev/null | head -30
ls -laS */C/Windows/System32/Logs 2>/dev/null | head -30
# is Sysmon there? if yes, prefer it over 4688
ls */C/Windows/System32/*/Logs | grep -i sysmon
# other artifacts
find . -name '$MFT' -o -name '$J' -o -name '*.pcap*' -o -name 'NTUSER.DAT' -o -name 'SYSTEM' -o -name '*.pf'
```

Build a host table early: hostname, IP (from 4624 IpAddress, pcap ARP, DNS), role (DC, SQL, workstation, attacker).

## 3. Decision tree by question type

| Question asks | Where to look |
|---|---|
| Earliest malicious activity | pcap first (ARP sweep / nmap SYN scan), then first 18456 / 4625 brute force |
| Attacker / origin IP | 18456 `[CLIENT: x]`, 4625/4624 `IpAddress`, `certutil http://IP:PORT` in 4688 |
| Which service was attacked | parent of the first shell: `sqlservr.exe` = MSSQL, `w3wp.exe` = IIS, `java.exe` = Tomcat |
| First remote command | first child of the service process (4688 ParentProcessName) or TDS `xp_cmdshell` in the pcap |
| Downloaded binary / URL | 4688 CommandLine with `certutil -urlcache`, `iwr`, `bitsadmin`, `curl` |
| Reverse shell time | 4688 of `nc.exe ... -e cmd.exe`, or the pcap SYN to the listener port plus the first `Microsoft Windows [Version` banner |
| PrivEsc command | 4688 with Potato tools (`SigmaPotato`, `GodPotato`, `PrintSpoofer`) after `whoami /priv` shows SeImpersonate |
| Exfil / staging | `reg save HKLM\SAM`, `net use X: \\IP\share /user:u p`, `copy`, then 4104 script blocks |
| Enumeration time | PowerShell 4104 (`dir C:\Users`, `Get-ADTrust`, `net user /domain`) |
| Credential stuffing / spraying | DC 4776 + 4625 burst from one IP, then the first 4624 success |
| Account compromised "without password" | 4768/4769 for a service account (Kerberoast, S4U, shadow creds, pass-the-hash NTLM 4624) |
| Logon GUID of privileged session | DC 4624 with `TransmittedServices` set (S4U2Proxy) - take `LogonGuid` |
| Lateral movement with admin tool | DC System 7045 random-named service (`%systemroot%\XXXXXXXX.exe`) = impacket psexec |
| Domain-wide compromise | DC 4662 with `1131f6ad-...` (Get-Changes-All) = DCSync |
| Trust enumeration | 4104 `Get-ADTrust -Filter *`, `nltest /domain_trusts` |

## 4. Answer-format gotchas

- Timestamps are UTC, `YYYY-MM-DD hh:mm:ss`, **truncated not rounded**.
- If a host-log timestamp is rejected, try the pcap time for the same event (network-observed time). Clocks drift by a few seconds.
- Paths: keep the exact case from the log, and unescape JSON `\\` to `\`.
- Domain\user masks like `XX-XXXX.XXXXXXXXX.XXX\xxxxxx` mean the FQDN in upper case and the user in lower case.
- Logon GUIDs: the mask is usually lower case (`xxxxxxxx-...`), while the log shows upper case in braces.
- When you submit from bash, use `read -r` or JSON-encode the answer, or backslashes get eaten.

## 5. Next docs

- `ctfbrain show cheatsheets:sherlocks:windows-evtx-hunting`
- `ctfbrain show cheatsheets:sherlocks:ad-attack-detection-event-ids`
- `ctfbrain show cheatsheets:sherlocks:pcap-dfir-tshark`
- `ctfbrain show scripts:sherlocks:evtx-to-jsonl-timeline`
- Worked example: `ctfbrain show writeups:sherlocks:htb-sasync`
