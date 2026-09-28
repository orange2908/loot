---
title: "Cheatsheet - Active Directory Attack Detection on the DC (Event IDs and jq)"
category: sherlocks
subcategory: active-directory
type: cheatsheet
tags: [active-directory, ad, domain-controller, kerberos, 4768, 4769, 4776, 4662, 4624, s4u2proxy, s4u2self, constrained-delegation, dcsync, psexec, impacket, credential-stuffing, password-spray, kerberoasting, golden-ticket, extrasids, logon-guid, sherlock, dfir]
summary: "What each AD attack leaves in DC Security/System logs and the jq to pull it out: spraying, Kerberoasting, S4U constrained delegation, DCSync, impacket psexec, child-to-parent trust abuse."
tools: [jq, evtx, chainsaw]
related: [windows-evtx-hunting, sherlock-triage, htb-sasync, kerberos-constrained-delegation-s4u-detection]
---

## Normalise once

```sh
# every command below assumes DC Security/System logs dumped to JSONL (scripts:sherlocks:evtx-to-jsonl-timeline)
DC=out/DC2
```

## One-shot auth overview (the most useful query)

```sh
# 4624/4625/4768/4769/4776/4648 with user, domain, ip, logon type, service, delegated services, logon guid, status
jq -r 'select(.Event.System.EventID|tostring|test("^(4624|4625|4768|4769|4771|4776|4648)$")) | .Event.EventData as $e | [._ts, .Event.System.EventID, ($e.TargetUserName//""), ($e.TargetDomainName//""), ($e.IpAddress//$e.Workstation//""), ($e.LogonType//""), ($e.ServiceName//""), ($e.TransmittedServices//""), ($e.LogonGuid//""), ($e.Status//""), ($e.AuthenticationPackageName//"")] | @tsv' $DC/Security.jsonl | grep -v -P '\t(DC\d?\$|SYSTEM|ANONYMOUS LOGON|DWM-\d|UMFD-\d)\t'
```

## Password spraying / credential stuffing

```sh
# NTLM validation on the DC: 4776 Status 0xc000006a = bad password, 0x0 = success
jq -r 'select(.Event.System.EventID==4776) | .Event.EventData as $e | [._ts, $e.TargetUserName, $e.Workstation, $e.Status] | @tsv' $DC/Security.jsonl
# failed network logons per source IP
jq -r 'select(.Event.System.EventID==4625) | .Event.EventData.IpAddress' $DC/Security.jsonl | sort | uniq -c | sort -rn
# first success from the spraying IP = first compromised domain account
jq -r 'select(.Event.System.EventID==4624 and .Event.EventData.IpAddress=="192.168.186.135") | [._ts, .Event.EventData.TargetUserName, .Event.EventData.AuthenticationPackageName] | @tsv' $DC/Security.jsonl | head -3
# Kerberos pre-auth failures (spray via Kerberos): 4771 status 0x18
jq -r 'select(.Event.System.EventID==4771) | .Event.EventData as $e | [._ts, $e.TargetUserName, $e.IpAddress, $e.Status] | @tsv' $DC/Security.jsonl
```

Pattern: one IP, many users, the same second, `0xc000006a` ... then one `0x0`.

## Kerberoasting / AS-REP roasting

```sh
# TGS requests with RC4 (0x17) for user SPNs
jq -r 'select(.Event.System.EventID==4769) | .Event.EventData as $e | select($e.TicketEncryptionType=="0x17") | [._ts, $e.TargetUserName, $e.ServiceName, $e.IpAddress] | @tsv' $DC/Security.jsonl
# AS-REP roast: 4768 with PreAuthType 0
jq -r 'select(.Event.System.EventID==4768) | .Event.EventData as $e | select($e.PreAuthType=="0") | [._ts, $e.TargetUserName, $e.IpAddress] | @tsv' $DC/Security.jsonl
```

## Constrained delegation abuse (S4U2Self + S4U2Proxy)

```sh
# 4768 TGT for the service account, then 4769 where the account requests a ticket to itself (S4U2Self)
jq -r 'select(.Event.System.EventID==4769) | .Event.EventData as $e | [._ts, $e.TargetUserName, $e.ServiceName, $e.IpAddress, ($e.TransmittedServices//"")] | @tsv' $DC/Security.jsonl
# the impersonated logon: 4624 for Administrator whose TransmittedServices names the service account
jq -r 'select(.Event.System.EventID==4624) | .Event.EventData as $e | select(($e.TransmittedServices//"-") != "-") | [._ts, $e.TargetUserName, $e.IpAddress, $e.TransmittedServices, $e.LogonGuid] | @tsv' $DC/Security.jsonl
```

- Feature: **Kerberos constrained delegation**. Extension: **S4U2Proxy** (plus protocol transition, S4U2Self).
- Tool side: `impacket-getST -spn cifs/dc.domain -impersonate Administrator domain/websvc -hashes :NT`.
- "Compromised without the password" usually means the hash or a ticket was used: an NTLM hash from a SAM/LSA dump, or roasting.
- The `LogonGuid` on that 4624 is the "escalated privileged session" GUID. Submit it lower case, without braces.

## Lateral movement to the DC

```sh
# impacket psexec: 7045 service with random name and %systemroot%\XXXXXXXX.exe, LocalSystem
jq -r 'select((.Event.System.EventID|if type=="object" then ."#text" else . end)==7045) | [._ts, .Event.EventData.ServiceName, .Event.EventData.ImagePath] | @tsv' $DC/System.jsonl
# then services.exe -> C:\Windows\XXXXXXXX.exe -> cmd.exe in 4688
jq -r 'select(.Event.System.EventID==4688) | .Event.EventData as $e | select($e.ParentProcessName|test("services.exe|\\\\Windows\\\\[A-Za-z]{8}\\.exe")) | [._ts, $e.ParentProcessName, $e.NewProcessName, $e.CommandLine] | @tsv' $DC/Security.jsonl
# other tools: PSEXESVC (sysinternals), WmiPrvSE children (wmiexec), 4698 scheduled task (atexec), wsmprovhost (winrm)
```

## DCSync

```sh
# 4662 on domainDNS object with replication GUIDs
jq -r 'select(.Event.System.EventID==4662) | [._ts, .Event.EventData.SubjectUserName, .Event.EventData.Properties] | @tsv' $DC/Security.jsonl
```

| GUID | Right |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All (secrets - the DCSync hit) |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |
| `19195a5b-6da0-11d0-afd3-00c04fd930c9` | domainDNS object class |

- A DCSync from a non-DC account is the classic signal. From SYSTEM on a DC the subject is `DC$`, so time-correlate it with `mimikatz.exe` in 4688.
- The event carrying `1131f6ad` is the successful abuse time.

## Trust enumeration and child-to-parent escalation

```sh
# enumeration in 4104
grep -h -o -E 'Get-ADTrust[^"]*|Get-ADForest|nltest[^"]*domain_trusts|Get-DomainTrust' $DC/Microsoft-Windows-PowerShell%4Operational.jsonl | sort -u
# golden ticket with ExtraSids to the parent: 4769 for Administrator@PARENT.DOMAIN from the child DC right after krbtgt was dumped
jq -r 'select(.Event.System.EventID==4769) | [._ts, .Event.EventData.TargetUserName, .Event.EventData.ServiceName] | @tsv' $DC/Security.jsonl | grep -i '@'
```

## Useful status and constant tables

| Code | Meaning |
|---|---|
| 0xc000006a | wrong password |
| 0xc0000064 | user does not exist |
| 0xc000006d | logon failure (generic, see SubStatus) |
| 0xc0000234 | locked out |
| 0x18 (4771) | Kerberos pre-auth failed (bad password) |
| 0x17 | RC4-HMAC ticket encryption (roasting) |
| 0x12 | AES256 |

## Pitfalls

- `TransmittedServices` keeps embedded `\r\n\t\t` whitespace, so match with `test("websvc")`.
- Several 4624 events can share one LogonGuid. The answer is the GUID, not the count.
- The DC event host may be a child-domain DC (for example `DB-TEST.SHANOCORP.HTB`). Masks like `XX-XXXX.XXXXXXXXX.XXX\user` want that FQDN.
