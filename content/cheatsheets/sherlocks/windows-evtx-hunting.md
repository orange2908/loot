---
title: "Cheatsheet - Windows Event Log (EVTX) Hunting for Sherlocks"
category: sherlocks
subcategory: evtx
type: cheatsheet
tags: [evtx, windows-event-logs, event-id, 4688, 4624, 4625, 4104, 7045, 18456, sysmon, jq, evtx-dump, pyevtx-rs, chainsaw, hayabusa, process-creation, powershell-scriptblock, mssql, dfir, sherlock]
summary: "Linux-only EVTX workflow: dump to JSONL with the Rust evtx parser, then jq one-liners for process trees, logons, PowerShell script blocks, service installs and MSSQL brute force."
tools: [evtx, jq, chainsaw, hayabusa, evtx_dump]
related: [sherlock-triage, ad-attack-detection-event-ids, evtx-to-jsonl-timeline]
---

## Setup (no Windows needed)

```sh
# Rust-backed parser with Python bindings: fast, handles dirty logs
uv venv .venv && uv pip install -p .venv evtx
# alternative CLI from the same project
cargo install evtx   # gives evtx_dump
# optional sigma-based hunters
# chainsaw: https://github.com/WithSecureLabs/chainsaw  hayabusa: https://github.com/Yamato-Security/hayabusa
```

## Dump every log to JSONL (one record per line)

```sh
# see scripts:sherlocks:evtx-to-jsonl-timeline for the script
.venv/bin/python dump.py HOST/C/Windows/System32/winevt/Logs out/HOST
# evtx_dump alternative, one file
evtx_dump -o jsonl Security.evtx > Security.jsonl
```

## Event ID census (find out what you actually have)

```sh
# the EventID field is either an int or {"#text": int}
jq -r '.Event.System.EventID | if type=="object" then ."#text" else . end' out/HOST/Security.jsonl | sort | uniq -c | sort -rn | head -20
# which logs have events in the attack window
for f in out/HOST/*.jsonl; do n=$(jq -r ._ts "$f" | awk '$1>"2026-03-09T19:25" && $1<"2026-03-09T19:45"' | wc -l); [ "$n" -gt 0 ] && echo "$n $f"; done | sort -rn
```

## Process creation - Security 4688 (needs cmdline auditing)

```sh
# full process timeline as TSV: time, user, parent, image, cmdline
jq -r 'select(.Event.System.EventID==4688) | .Event.EventData as $e | [._ts, $e.SubjectUserName, ($e.ParentProcessName//"-"), $e.NewProcessName, ($e.CommandLine//"")] | @tsv' Security.jsonl > 4688.tsv
# parent census - odd parents (sqlservr, w3wp, java, nc) stand out
cut -f3 4688.tsv | sort | uniq -c | sort -rn | head -30
# drop the noise and keep what matters
grep -v -E 'ngen.exe|msiexec|EdgeUpdate|msedge|VMware|Defender|dsregcmd|conhost.exe' 4688.tsv | grep -i -E 'sqlservr|w3wp|cmd.exe|powershell|certutil|net.exe|reg.exe|Temp|Public|whoami'
# children of the SQL Server service = xp_cmdshell
awk -F'\t' '$3 ~ /sqlservr.exe/' 4688.tsv
# LOLBin downloads
grep -i -E 'certutil.*urlcache|bitsadmin|Invoke-WebRequest|iwr |wget |curl ' 4688.tsv
# credential dumping
grep -i -E 'reg(.exe)?"? save|mimikatz|procdump|comsvcs|ntdsutil|vssadmin' 4688.tsv
```

## Sysmon (if present) - richer than 4688

```sh
# 1 process, 3 network, 11 file create, 13 registry, 22 dns
jq -r 'select(.Event.System.EventID==1) | .Event.EventData | [.UtcTime, .User, .ParentImage, .Image, .CommandLine] | @tsv' Sysmon.jsonl
jq -r 'select(.Event.System.EventID==3) | .Event.EventData | [.UtcTime, .Image, .DestinationIp, .DestinationPort] | @tsv' Sysmon.jsonl
```

## Logons - Security 4624 / 4625 / 4648

```sh
# 4624 with source IP, logon type, auth package, logon GUID, delegated services
jq -r 'select(.Event.System.EventID==4624) | .Event.EventData as $e | [._ts, $e.TargetUserName, $e.TargetDomainName, $e.IpAddress, $e.LogonType, $e.AuthenticationPackageName, $e.LogonGuid, ($e.TransmittedServices//"")] | @tsv' Security.jsonl | grep -v -E '\t(SYSTEM|DWM-|UMFD-|ANONYMOUS LOGON)'
# failures with status (0xc000006a bad password, 0xc0000064 no such user)
jq -r 'select(.Event.System.EventID==4625) | .Event.EventData as $e | [._ts, $e.TargetUserName, $e.IpAddress, $e.Status, $e.SubStatus] | @tsv' Security.jsonl
# explicit creds (runas, psexec -u)
jq -r 'select(.Event.System.EventID==4648) | .Event.EventData as $e | [._ts, $e.SubjectUserName, $e.TargetUserName, $e.TargetServerName, $e.ProcessName] | @tsv' Security.jsonl
# logon types: 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 9 newcreds, 10 RDP
```

## PowerShell - 4104 script blocks (the attacker's typed commands)

```sh
jq -r 'select(.Event.System.EventID==4104) | [._ts, (.Event.EventData.ScriptBlockText|gsub("\n";" | "))] | @tsv' "Microsoft-Windows-PowerShell%4Operational.jsonl" | cut -c1-300
# drop module-loading noise
... | grep -v -E 'cmdletization|Set-StrictMode|^\S+ \S+\tprompt$|\$Host'
# classic PowerShell log: 400 engine start, 600 provider, 800 pipeline
jq -r 'select(.Event.System.EventID==400) | [._ts, (.Event.EventData.Data."#text"|tostring|.[0:300])] | @tsv' "Windows PowerShell.jsonl"
# decode -e / -EncodedCommand blobs (UTF-16LE base64)
echo 'DQAKAFQAcgB5AA==' | base64 -d | iconv -f utf-16le -t utf-8
```

## Services - System 7045 / 7036

```sh
# random 8-char exe under %systemroot% = impacket psexec / smbexec
jq -r 'select((.Event.System.EventID|if type=="object" then ."#text" else . end)==7045) | [._ts, .Event.EventData.ServiceName, .Event.EventData.ImagePath, .Event.EventData.AccountName] | @tsv' System.jsonl
# PSEXESVC = Sysinternals PsExec
grep -i psexesvc System.jsonl | jq -r '._ts'
```

## MSSQL - Application log

```sh
# 18456 failed login with client IP - brute force burst
jq -r 'select((.Event.System.EventID|if type=="object" then ."#text" else . end)==18456) | [._ts, (.Event.EventData.Data."#text"|join(" "))] | @tsv' Application.jsonl | head
# count per source
jq -r 'select((.Event.System.EventID|if type=="object" then ."#text" else . end)==18456) | .Event.EventData.Data."#text"[2]' Application.jsonl | sort | uniq -c
# 15457 config change (xp_cmdshell enabled), 18454/18453 successful logins (only if success auditing is on)
jq -c 'select((.Event.System.EventID|if type=="object" then ."#text" else . end|tostring)|test("^(15457|18453|18454)$")) | [._ts, .Event.EventData.Data]' Application.jsonl
```

## Anti-forensics

```sh
# log clearing: Security 1102, System 104, or wevtutil cl in 4688
jq -r 'select(.Event.System.EventID==1102) | ._ts' Security.jsonl
grep -h 'wevtutil' 4688.tsv
# 4616 time change
```

## Chainsaw / Hayabusa quick hunts

```sh
chainsaw hunt HOST/C/Windows/System32/winevt/Logs -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o hunt.csv --csv
chainsaw search "xp_cmdshell" HOST/C/Windows/System32/winevt/Logs
hayabusa csv-timeline -d HOST/C/Windows/System32/winevt/Logs -o timeline.csv
```

## Pitfalls

- Some triage packs put logs in `System32/Logs` instead of `System32/winevt/Logs`. Point the tools at wherever the `.evtx` files are.
- The `_ts` record timestamp is UTC. `TimeCreated.SystemTime` is the same value.
- `EventID` is sometimes an object carrying `Qualifiers` (System, Application). Always normalise it.
- Files extracted from the zip can end up without read permission for some tools. Copy them to a scratch dir, or `chmod -R u+rwX .`.
