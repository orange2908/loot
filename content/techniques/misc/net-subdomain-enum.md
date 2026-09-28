---
title: "Subdomain Enumeration and Virtual Host Discovery"
category: misc
subcategory: recon
type: technique
tags: [subfinder, amass, assetfinder, crtsh, certificate-transparency, ffuf, gobuster, vhost-fuzzing, dnsx, puredns, massdns, wildcard-dns, subdomain-enumeration, virtual-host, recon, dig]
difficulty: easy
summary: "Passive CT-log harvesting plus active DNS brute force finds real subdomains; Host-header fuzzing finds vhosts that have no DNS record at all."
when_to_use:
  - "A CTF box serves a placeholder page and hints at a domain name"
  - "You have a domain and need the attack surface behind it"
  - "A TLS certificate SAN list or a redirect leaked an internal hostname"
  - "DNS brute force found nothing but the web server clearly serves multiple sites"
tools: [subfinder, amass, assetfinder, ffuf, gobuster, dnsx, puredns, massdns, dig, httpx]
related: [net-dns-attacks, net-content-discovery, net-scanning-fingerprinting]
---

## TL;DR

Two *different* problems that people confuse:

1. **Subdomain enumeration** -- which names resolve in DNS. Solved passively (CT logs, APIs) and
   actively (DNS brute force).
2. **Virtual host discovery** -- which `Host:` values a *known IP* serves differently. There may be
   no DNS record at all. Solved by fuzzing the Host header and filtering on response size.

In an offline CTF you almost always want #2, because there is no public DNS for `target.ctf`.

## Recognise it

- `nmap` gave you an IP; the HTTP response redirects to `http://something.htb/`.
- A TLS certificate's `subjectAltName` lists names you have never seen.
- The default nginx/Apache page is served for the IP, but a name gives a real app.
- A challenge says "the flag is on the dev instance".

## Attack

### Step 0 -- collect names you already have for free

```bash
# Names in the TLS certificate (SAN list is a free subdomain list)
openssl s_client -connect 10.10.10.5:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'

# Same via nmap
nmap -p443 --script ssl-cert 10.10.10.5

# Where does the bare IP redirect to?
curl -sI http://10.10.10.5/ | grep -i '^location'

# Names referenced in the page source, JS bundles and comments
curl -s http://target.ctf | grep -oE '[a-z0-9._-]+\.target\.ctf' | sort -u
```

Put everything you find into `/etc/hosts` immediately:

```bash
# Map every discovered name to the box IP so the browser and tools resolve it
printf '10.10.10.5\ttarget.ctf www.target.ctf dev.target.ctf admin.target.ctf\n' | sudo tee -a /etc/hosts
```

### Step 1 -- passive enumeration (internet-facing targets only)

```bash
# subfinder: many sources at once, silent output suitable for piping
subfinder -d target.com -all -silent -o subs-passive.txt

# assetfinder, including subdomains of subdomains
assetfinder --subs-only target.com | sort -u >> subs-passive.txt

# amass passive mode (active mode also does brute force and zone walking)
amass enum -passive -d target.com -o subs-amass.txt

# crt.sh certificate transparency via its JSON endpoint
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | tr '\n' '\n' | sed 's/^\*\.//' | sort -u

# Certificate transparency without jq, using the same endpoint
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | grep -oE '[a-zA-Z0-9._-]+\.target\.com' | sort -u
```

CT logs are the highest-yield passive source: every publicly issued certificate is logged, so
`dev.`, `staging.`, `vpn.` and `jenkins.` names leak there constantly.

### Step 2 -- resolve and keep only what is live

```bash
# Resolve a candidate list fast and keep resolvable names with their A records
dnsx -l subs-all.txt -a -resp -silent -o resolved.txt

# massdns with a public resolver list
massdns -r resolvers.txt -t A -o S -w massdns.out subs-all.txt

# Probe which resolved names actually answer over HTTP/HTTPS
httpx -l resolved.txt -status-code -title -tech-detect -follow-redirects -o live.txt
```

### Step 3 -- active DNS brute force

```bash
# ffuf against the DNS-resolving layer by fuzzing the Host header is NOT this;
# this is real DNS brute force with gobuster dns mode
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50 -i

# puredns: brute force with wildcard filtering built in (the important part)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt target.com -r resolvers.txt

# dnsx brute force mode with a wordlist
dnsx -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -a -silent
```

Useful SecLists DNS wordlists:

```
/usr/share/seclists/Discovery/DNS/
  subdomains-top1million-5000.txt       # quick pass
  subdomains-top1million-20000.txt      # the standard
  subdomains-top1million-110000.txt     # deep pass
  bitquark-subdomains-top100000.txt     # good complement, different corpus
  dns-Jhaddix.txt                       # large mixed list
  namelist.txt                          # small, classic
```

### Step 4 -- detect and filter wildcard DNS

A wildcard record makes every name "resolve" and turns brute force into garbage.

```bash
# If a random name resolves, the zone has a wildcard
dig +short thisdoesnotexist-9f2k.target.com

# Compare two random names -- same IP means a wildcard, and you must filter by that IP
dig +short aaaa-random-1.target.com; dig +short bbbb-random-2.target.com
```

Filtering strategies:

- `puredns` handles wildcards natively (that is its main selling point).
- With ffuf/gobuster: discard every result whose A record equals the wildcard IP.
- If the wildcard points at a shared front end, filter on the **HTTP** response instead:
  fetch each name with `httpx` and drop those matching the wildcard body hash.

```bash
# Drop names that resolve to the known wildcard IP
awk -v wc="203.0.113.10" '$2 != wc' resolved.txt > resolved-filtered.txt
```

### Step 5 -- virtual host fuzzing (the CTF workhorse)

This does not touch DNS. You send `Host: candidate.target.ctf` to the IP and look for a response
that differs from the default site.

```bash
# Baseline: what does the server return for a bogus Host?
curl -s -o /dev/null -w 'size=%{size_download} status=%{http_code}\n' -H 'Host: nonexistent-9k2.target.ctf' http://10.10.10.5/

# Fuzz the Host header, hide everything the same size as the default response
ffuf -u http://10.10.10.5/ -H 'Host: FUZZ.target.ctf' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 1234

# Filter on word count instead when the body length varies
ffuf -u http://10.10.10.5/ -H 'Host: FUZZ.target.ctf' -w subdomains-top1million-5000.txt -fw 210

# Auto-calibration also works for vhosts
ffuf -u http://10.10.10.5/ -H 'Host: FUZZ.target.ctf' -w subdomains-top1million-5000.txt -ac

# gobuster vhost mode; --append-domain adds the base domain to each word
gobuster vhost -u http://10.10.10.5 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 50

# HTTPS vhosts need SNI: ffuf sends the right SNI when you fuzz the URL host,
# so fuzz with the -H Host plus an explicit resolve on curl for verification
curl -sk --resolve 'dev.target.ctf:443:10.10.10.5' https://dev.target.ctf/ | head
```

Confirm every hit by hand and add it to `/etc/hosts`:

```bash
# Verify a candidate vhost directly
curl -s -H 'Host: dev.target.ctf' http://10.10.10.5/ | head -20
```

### Step 6 -- permutations and second-level expansion

```bash
# Generate permutations (dev-api, api-dev, api1, api2 ...) from known names
gotator -sub known.txt -perm permutations.txt -depth 2 -numbers 3 -silent > perms.txt

# Then resolve them
dnsx -l perms.txt -a -silent -o perms-resolved.txt

# Recurse: brute force subdomains OF a discovered subdomain
gobuster dns -d dev.target.com -w subdomains-top1million-5000.txt
```

Manual permutation list worth trying on every CTF box:
`dev, test, staging, stage, uat, qa, admin, portal, intranet, internal, git, gitlab, jenkins,
ci, api, api-dev, mail, smtp, webmail, vpn, ns1, ns2, ftp, files, backup, db, monitor,
grafana, kibana, jira, wiki, docs, static, cdn, img, assets, old, new, beta, demo, shop, store`.

### Step 7 -- feed results back into recon

```bash
# Scan every discovered vhost for content separately -- they differ
ffuf -u http://dev.target.ctf/FUZZ -w raft-medium-directories.txt -ac

# Screenshot everything at once to triage visually
httpx -l live.txt -screenshot -srd shots/
```

## Code

Host-header fuzzer with automatic baseline calibration -- no external tools, handy when you only
have Python on a jump box.

```python
#!/usr/bin/env python3
"""Virtual host fuzzer with automatic baseline calibration.

Usage:
    python3 vhostfuzz.py http://10.10.10.5 target.ctf wordlist.txt [threads]
"""
from __future__ import annotations

import hashlib
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TIMEOUT = 8


def fetch(base: str, host: str) -> tuple[int, int, str]:
    """Request base URL with an explicit Host header; return status, length, body hash."""
    req = Request(base, headers={"Host": host, "User-Agent": "vhostfuzz/1.0"})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
            return resp.status, len(body), hashlib.sha1(body).hexdigest()[:10]
    except HTTPError as exc:
        body = exc.read()
        return exc.code, len(body), hashlib.sha1(body).hexdigest()[:10]
    except (URLError, OSError):
        return 0, 0, "error"


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(__doc__)
        return 1
    base, domain, wordlist = argv[1], argv[2], argv[3]
    threads = int(argv[4]) if len(argv) > 4 else 20

    baselines: set[tuple[int, int]] = set()
    for probe in ("zzq1-nope", "zzq2-nope", "zzq3-nope"):
        status, length, _ = fetch(base, f"{probe}.{domain}")
        baselines.add((status, length))
    print(f"[*] baseline responses: {sorted(baselines)}", file=sys.stderr)

    with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
        words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]

    def probe_one(word: str) -> None:
        host = f"{word}.{domain}"
        status, length, digest = fetch(base, host)
        if status == 0:
            return
        if (status, length) in baselines:
            return
        print(f"[+] {host:<45} status={status} len={length} body={digest}")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(probe_one, words))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **DNS brute force vs vhost fuzzing.** On an offline CTF network there is usually no DNS server
  for the target domain -- brute forcing DNS returns nothing while vhost fuzzing finds five sites.
  If `dig` fails but HTTP works, go straight to Host-header fuzzing.
- **Wildcard DNS** makes everything "resolve". Detect it with a random label before you trust results.
- **Wildcard vhosts.** Some servers return the default site for every unknown Host; your filter
  then hides real hits that happen to be the same size. Cross-check a few by hand.
- **HTTPS + SNI.** The TLS SNI and the HTTP Host must both be the candidate name, or you get the
  default certificate and default site. Use `curl --resolve` for verification.
- **Case and trailing dot.** `Host: DEV.target.ctf` and `Host: dev.target.ctf.` sometimes bypass
  a naive vhost ACL -- worth one manual try.
- **Port in the Host header.** Some apps compare `Host` including the port; try
  `Host: dev.target.ctf:80` if the clean name fails.
- **Rate limits.** Passive sources (crt.sh) will throttle you; cache results to a file.
- **Scope.** Only enumerate domains you are allowed to touch. Passive CT queries hit third-party
  services -- in an offline CTF they will simply fail, which is expected.

## Tools

- `subfinder`, `assetfinder`, `amass` -- passive source aggregation.
- `crt.sh` -- certificate transparency search (public internet only).
- `puredns` + `massdns` -- high-speed resolution with wildcard filtering.
- `dnsx` -- resolution, brute force and record extraction in one binary.
- `ffuf` / `gobuster vhost` -- Host-header fuzzing.
- `httpx` -- live-host probing, titles, tech detection, screenshots.
- `gotator` / `dnsgen` -- permutation generation.

## References

- RFC 6962 (Certificate Transparency) -- why CT logs leak subdomain names.
- RFC 7230 section 5.4 -- the `Host` header and name-based virtual hosting.
- SecLists `Discovery/DNS/` wordlists.
