---
title: "Domain and Infrastructure OSINT"
category: osint
subcategory: infrastructure
type: technique
tags: [osint, whois, rdap, dns, subdomain-enumeration, certificate-transparency, crt-sh, passive-dns, amass, subfinder, dnsx, wayback, cdx, favicon-hash, shodan, censys, spf, dmarc, asn]
difficulty: medium
summary: "whois/RDAP for ownership, certificate transparency and passive DNS for names, DNS records for services, and the Wayback CDX API for history."
when_to_use:
  - "The challenge gives a domain and asks for a hidden host, an IP or an owner"
  - "You need every subdomain of a target without touching it"
  - "A site changed and you need the old content or the old URL list"
  - "You must tie an IP or a favicon back to an organisation"
tools: [whois, dig, crt.sh, amass, subfinder, dnsx, httpx, wayback, shodan, censys]
related: [osint-methodology, osint-social-and-archives, osint-documents-and-code, osint-tools-cheatsheet, git-data-recovery]
---

## TL;DR

Four passive sources answer almost every infrastructure question: **RDAP/whois** (who
registered it and when), **certificate transparency** (every hostname anyone ever got a
certificate for), **DNS records** (what exists now, including TXT and mail policy), and the
**Wayback Machine CDX API** (every URL the archive ever saw). None of them touch the target.

## Recognise it

- "What is the IP of ...", "find the hidden subdomain", "who registered this domain",
  "what was on this page in 2021", "what is the admin's email".
- A domain that was clearly registered for the challenge (created days before the event).
- A challenge that hands you an IP or a favicon and asks which organisation it belongs to.

## Registration data

```bash
# classic whois
whois example.com
whois -h whois.iana.org example.com          # find the authoritative registry first
whois 93.184.216.34                          # IP allocation, netblock, abuse contact

# RDAP: the structured, JSON successor to whois
curl -s https://rdap.org/domain/example.com | jq .
curl -s https://rdap.org/ip/93.184.216.34 | jq .

# ASN and netblock for an IP, via the Team Cymru whois service
whois -h whois.cymru.com " -v 93.184.216.34"
```

What to read: `Creation Date` (a domain created last week is the challenge artifact),
registrar, name servers, and any contact that is not redacted. Historical whois is mostly
paywalled - prefer certificate transparency and archives for history.

## DNS

```bash
# the full sweep
for t in A AAAA MX NS SOA TXT CAA SRV; do echo "== $t"; dig +short "$t" example.com; done
dig +short ANY example.com                  # mostly refused now, but worth one try
dig +trace example.com                      # the delegation chain
dig -x 93.184.216.34 +short                 # reverse lookup

# mail policy records, which leak providers and sometimes hostnames
dig +short TXT example.com | grep -i spf
dig +short TXT _dmarc.example.com
dig +short TXT selector1._domainkey.example.com
dig +short TXT _domainkey.example.com

# zone transfer - almost always refused, but free to try
for ns in $(dig +short NS example.com); do dig AXFR example.com @"$ns"; done

# DNSSEC and wildcard detection
dig +dnssec example.com
dig +short definitely-not-a-real-host-12345.example.com     # non-empty = wildcard

# resolve a list of candidate names quickly
dnsx -l names.txt -a -resp -silent
massdns -r resolvers.txt -t A -o S names.txt
```

SPF records are a goldmine: `v=spf1 include:_spf.google.com ip4:203.0.113.0/24 -all` tells you
the mail provider and a netblock the organisation owns.

## Certificate transparency

Every publicly trusted certificate is logged. That means **every hostname anyone ever
requested a certificate for is public**, including internal-sounding ones.

```bash
# crt.sh, JSON output
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | \
  tr '\\n' '\n' | sed 's/^\*\.//' | sort -u

# a single certificate by id
curl -s 'https://crt.sh/?id=123456789&output=json' | jq .

# search by organisation name rather than by domain
curl -s 'https://crt.sh/?O=Example+Inc&output=json' | jq -r '.[].name_value' | sort -u

# inspect the live certificate, including its SAN list
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -text | grep -A2 'Subject Alternative Name'
```

Censys and Shodan index certificates and banners too, and let you search by certificate
fingerprint, JARM, or HTTP body hash - both need a free account for the API.

## Subdomain enumeration

```bash
# passive: many sources at once, no traffic to the target
subfinder -d example.com -all -silent
amass enum -passive -d example.com
amass intel -d example.com -whois            # related domains by registration data
assetfinder --subs-only example.com

# active: resolve a wordlist (this DOES touch DNS servers)
dnsx -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent
ffuf -u https://FUZZ.example.com -w wordlist.txt -mc all -fs 0

# permutations of the names you already have
dnsgen names.txt | dnsx -silent
altdns -i names.txt -o perms.txt -w words.txt

# then probe which ones are alive and what they run
httpx -l names.txt -title -tech-detect -status-code -silent
```

Order matters: passive first (free, silent, usually enough for CTF), permutations second,
brute force last.

## Historical content

```bash
# every URL the Wayback Machine has for a host
curl -s 'https://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=5000'

# just the unique paths
curl -s 'https://web.archive.org/cdx/search/cdx?url=example.com*&fl=original&collapse=urlkey' | \
  sed 's|https\?://[^/]*||' | sort -u

# a specific snapshot
curl -s 'https://web.archive.org/web/20210101000000/https://example.com/'
# the closest snapshot to a date, via the availability API
curl -s 'https://archive.org/wayback/available?url=example.com&timestamp=20210101' | jq .

# tools that wrap the same API
waybackurls example.com
gau example.com
```

The CDX API is the single most useful OSINT endpoint for web challenges: it gives you a
historical URL list including files that were deleted (`.git`, `.env`, backups, old admin
paths). Cross-reference with `archive.today` for pages the Internet Archive does not have.

## Fingerprinting an organisation from an artifact

```bash
# favicon hash: Shodan indexes the mmh3 hash of the base64-encoded favicon
python3 -c "
import base64, sys, urllib.request
import mmh3                                  # pip install mmh3
d = urllib.request.urlopen(sys.argv[1]).read()
print('http.favicon.hash:%d' % mmh3.hash(base64.encodebytes(d)))" https://example.com/favicon.ico
# then search that value on Shodan

# HTTP fingerprints
curl -sI https://example.com | tee headers.txt
curl -s https://example.com | grep -iE '<title>|generator|X-Powered-By'

# the well-known files people forget
curl -s https://example.com/robots.txt
curl -s https://example.com/sitemap.xml
curl -s https://example.com/.well-known/security.txt
curl -s https://example.com/humans.txt
curl -s https://example.com/crossdomain.xml
curl -s https://example.com/.well-known/openid-configuration | jq .
```

## Code

```python
#!/usr/bin/env python3
"""Passive infrastructure recon: crt.sh, Wayback CDX, DNS parsing, favicon hashing.

Network calls degrade gracefully, so the self-test passes offline.

  python3 infra.py crt example.com
  python3 infra.py wayback example.com
  python3 infra.py spf "v=spf1 include:_spf.google.com ip4:203.0.113.0/24 -all"
  python3 infra.py --selftest
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; ctf-osint/1.0)"
HOST_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
                     r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)+$")


def fetch(url: str, timeout: int = 30) -> bytes | None:
    """GET a URL, returning None on any network failure (so callers stay offline-safe)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


# --------------------------------------------------------------------------- #
# certificate transparency
# --------------------------------------------------------------------------- #
def crtsh_url(domain: str, by_org: bool = False) -> str:
    if by_org:
        return "https://crt.sh/?O=" + urllib.parse.quote(domain) + "&output=json"
    return "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"


def parse_crtsh(payload: bytes, domain: str | None = None) -> list[str]:
    """Extract unique hostnames from crt.sh JSON (name_value holds newline-separated SANs)."""
    try:
        rows = json.loads(payload.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return []
    names: set[str] = set()
    for row in rows:
        for field in ("name_value", "common_name"):
            val = row.get(field) or ""
            for name in str(val).split("\n"):
                name = name.strip().lstrip("*.").lower().rstrip(".")
                if not name or not HOST_RE.match(name):
                    continue
                if domain and not (name == domain or name.endswith("." + domain)):
                    continue
                names.add(name)
    return sorted(names)


def crtsh(domain: str) -> list[str]:
    payload = fetch(crtsh_url(domain))
    return parse_crtsh(payload, domain) if payload else []


# --------------------------------------------------------------------------- #
# wayback CDX
# --------------------------------------------------------------------------- #
def cdx_url(target: str, limit: int = 5000, collapse: bool = True) -> str:
    q = {
        "url": target,
        "output": "json",
        "fl": "original,timestamp,statuscode,mimetype",
        "limit": str(limit),
    }
    if collapse:
        q["collapse"] = "urlkey"
    return "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(q)


def parse_cdx(payload: bytes) -> list[dict]:
    """CDX JSON is a header row followed by value rows."""
    try:
        rows = json.loads(payload.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return []
    if not rows:
        return []
    header, *values = rows
    return [dict(zip(header, row)) for row in values]


def interesting_paths(entries: list[dict]) -> list[str]:
    """Archived URLs that tend to matter: configs, backups, VCS, admin, uploads."""
    patterns = (".git", ".svn", ".env", ".bak", ".old", ".sql", ".zip", ".tar",
                "backup", "admin", "config", "dump", "secret", "key", "token",
                "upload", "private", "internal", "test", "dev", "staging",
                "wp-config", "id_rsa", ".DS_Store", "swagger", "api-docs")
    out = []
    for e in entries:
        url = str(e.get("original", ""))
        low = url.lower()
        if any(p in low for p in patterns):
            out.append(url)
    return sorted(set(out))


def wayback(target: str) -> list[dict]:
    payload = fetch(cdx_url(target))
    return parse_cdx(payload) if payload else []


def availability_url(target: str, timestamp: str = "") -> str:
    q = {"url": target}
    if timestamp:
        q["timestamp"] = timestamp
    return "https://archive.org/wayback/available?" + urllib.parse.urlencode(q)


# --------------------------------------------------------------------------- #
# DNS record parsing
# --------------------------------------------------------------------------- #
def parse_spf(record: str) -> dict:
    """Pull includes, ip4/ip6 netblocks, a/mx mechanisms and the policy out of an SPF record."""
    out: dict = {"includes": [], "ip4": [], "ip6": [], "a": [], "mx": [],
                 "redirect": None, "all": None, "exists": []}
    if not record.lower().startswith("v=spf1"):
        return out
    for token in record.split()[1:]:
        low = token.lower()
        if low.startswith("include:"):
            out["includes"].append(token[8:])
        elif low.startswith("ip4:"):
            out["ip4"].append(token[4:])
        elif low.startswith("ip6:"):
            out["ip6"].append(token[4:])
        elif low.startswith("redirect="):
            out["redirect"] = token[9:]
        elif low.startswith("exists:"):
            out["exists"].append(token[7:])
        elif low in ("a", "mx"):
            out[low].append("self")
        elif low.startswith("a:"):
            out["a"].append(token[2:])
        elif low.startswith("mx:"):
            out["mx"].append(token[3:])
        elif low.endswith("all"):
            out["all"] = token
    return out


def parse_dmarc(record: str) -> dict:
    out: dict = {}
    if not record.lower().startswith("v=dmarc1"):
        return out
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip().lower()] = v.strip()
    return out


MAIL_PROVIDERS = {
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "servers.mcsv.net": "Mailchimp",
    "spf.mandrillapp.com": "Mandrill",
    "zoho.com": "Zoho Mail",
    "_spf.mail.yandex.net": "Yandex Mail",
    "mailtrap.io": "Mailtrap",
}


def identify_providers(spf: dict) -> list[str]:
    out = []
    for inc in spf.get("includes", []):
        for needle, name in MAIL_PROVIDERS.items():
            if needle in inc:
                out.append(name)
    return sorted(set(out))


# --------------------------------------------------------------------------- #
# favicon hash
# --------------------------------------------------------------------------- #
def favicon_query(data: bytes) -> str | None:
    """Shodan's http.favicon.hash is mmh3 of the base64-encoded favicon bytes."""
    import base64
    try:
        import mmh3
    except ImportError:
        return None
    return f"http.favicon.hash:{mmh3.hash(base64.encodebytes(data))}"


WELL_KNOWN = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt",
    "/crossdomain.xml", "/.well-known/openid-configuration", "/.git/HEAD",
    "/.env", "/server-status", "/.well-known/change-password",
]


def well_known_urls(base: str) -> list[str]:
    base = base.rstrip("/")
    return [base + p for p in WELL_KNOWN]


# --------------------------------------------------------------------------- #
def main(argv: list[str]) -> int:
    if not argv or argv[0] == "--selftest":
        _selftest()
        return 0
    cmd = argv[0]
    if cmd == "crt":
        names = crtsh(argv[1])
        if not names:
            print(f"[-] no results (offline?). Query by hand: {crtsh_url(argv[1])}")
            return 1
        print("\n".join(names))
    elif cmd == "wayback":
        entries = wayback(argv[1] + "/*")
        if not entries:
            print(f"[-] no results (offline?). Query by hand: {cdx_url(argv[1] + '/*')}")
            return 1
        print(f"[i] {len(entries)} archived URLs")
        for url in interesting_paths(entries):
            print("  !! " + url)
    elif cmd == "spf":
        spf = parse_spf(argv[1])
        print(json.dumps(spf, indent=2))
        print("providers: " + ", ".join(identify_providers(spf)) or "unknown")
    elif cmd == "wellknown":
        print("\n".join(well_known_urls(argv[1])))
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    # crt.sh URL construction and parsing
    assert crtsh_url("example.com") == "https://crt.sh/?q=%25.example.com&output=json"
    assert "O=Example%20Inc" in crtsh_url("Example Inc", by_org=True)
    sample = json.dumps([
        {"name_value": "www.example.com\n*.example.com", "common_name": "example.com"},
        {"name_value": "dev.internal.example.com", "common_name": "dev.internal.example.com"},
        {"name_value": "unrelated.test", "common_name": "unrelated.test"},
        {"name_value": "not a hostname!!", "common_name": ""},
    ]).encode()
    names = parse_crtsh(sample, "example.com")
    assert names == ["dev.internal.example.com", "example.com", "www.example.com"], names
    assert parse_crtsh(b"not json") == []
    assert "unrelated.test" in parse_crtsh(sample)      # unfiltered keeps everything

    # CDX URL and parsing
    u = cdx_url("example.com/*")
    assert "web.archive.org/cdx/search/cdx" in u and "collapse=urlkey" in u
    cdx_sample = json.dumps([
        ["original", "timestamp", "statuscode", "mimetype"],
        ["https://example.com/index.html", "20210101000000", "200", "text/html"],
        ["https://example.com/backup.zip", "20210102000000", "200", "application/zip"],
        ["https://example.com/.git/config", "20210103000000", "200", "text/plain"],
        ["https://example.com/style.css", "20210104000000", "200", "text/css"],
    ]).encode()
    entries = parse_cdx(cdx_sample)
    assert len(entries) == 4 and entries[0]["original"].endswith("index.html")
    interesting = interesting_paths(entries)
    assert "https://example.com/backup.zip" in interesting
    assert "https://example.com/.git/config" in interesting
    assert "https://example.com/style.css" not in interesting
    assert parse_cdx(b"[]") == []
    assert "timestamp=20210101" in availability_url("example.com", "20210101")

    # SPF parsing
    spf = parse_spf("v=spf1 include:_spf.google.com include:spf.protection.outlook.com "
                    "ip4:203.0.113.0/24 ip6:2001:db8::/32 a:mail.example.com mx -all")
    assert spf["includes"] == ["_spf.google.com", "spf.protection.outlook.com"], spf
    assert spf["ip4"] == ["203.0.113.0/24"] and spf["ip6"] == ["2001:db8::/32"]
    assert spf["a"] == ["mail.example.com"] and spf["mx"] == ["self"]
    assert spf["all"] == "-all"
    assert identify_providers(spf) == ["Google Workspace", "Microsoft 365"]
    assert parse_spf("not an spf record")["includes"] == []

    # DMARC parsing
    d = parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100")
    assert d["p"] == "reject" and d["rua"] == "mailto:dmarc@example.com" and d["pct"] == "100"
    assert parse_dmarc("v=spf1 -all") == {}

    # hostname validation
    assert HOST_RE.match("a.b.example.com") and HOST_RE.match("x-1.example.co.uk")
    assert not HOST_RE.match("no-dot") and not HOST_RE.match("bad space.com")

    # well-known list
    wk = well_known_urls("https://example.com/")
    assert "https://example.com/robots.txt" in wk and "https://example.com/.git/HEAD" in wk

    # network calls must not raise when offline
    assert fetch("http://127.0.0.1:1/definitely-not-listening", timeout=2) is None

    print(f"selftest ok: crt.sh parsing ({len(names)} names), CDX parsing "
          f"({len(interesting)} interesting URLs), SPF/DMARC parsing, offline-safe fetch")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

## Variants and pitfalls

- **Certificate transparency beats brute force.** A single crt.sh query finds internal-sounding
  hostnames a wordlist never will, and it sends zero packets to the target.
- **Wildcard DNS ruins active enumeration.** Always test a random hostname first; if it
  resolves, filter your results by response content, not by resolution.
- **crt.sh is often slow or rate limited.** Retry, or use the `?q=` form with `%25.` (a
  URL-encoded `%`) for the wildcard.
- **whois for `.uk`, `.de`, `.fr` and others is heavily redacted.** RDAP is more consistent but
  redacts the same personal data. Historical whois is paywalled; do not build a plan on it.
- **`dig ANY` is mostly dead**; ask for each record type explicitly.
- **Passive DNS aggregators need accounts.** For a CTF, crt.sh plus the Wayback CDX API is
  usually enough.
- **The CDX API's `collapse=urlkey`** deduplicates; drop it if you want every snapshot of one
  page over time (useful for diffing a page's history).
- **archive.today complements the Internet Archive**, especially for pages that block the
  crawler or were saved on request.
- **Do not attack what you find.** Enumeration is OSINT; hitting the host may be out of scope.
- **A domain registered days before the event is the challenge's own**. Sort by creation date.
- **Check `security.txt` and `openid-configuration`** - they are designed to be public and
  frequently name people, emails and internal hostnames.

## Tools

`whois`, `dig`, RDAP (`https://rdap.org/`), crt.sh, `subfinder`, `amass`, `assetfinder`,
`dnsx`, `massdns`, `httpx`, `dnsgen`, Shodan and Censys (free accounts), the Wayback Machine
CDX API, `waybackurls`, `gau`, `archive.today`.

## References

- crt.sh, the Sectigo-operated certificate transparency search interface: https://crt.sh/
- Wayback Machine CDX Server API documentation:
  https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
- RFC 7208 (SPF) and RFC 7489 (DMARC) for the record syntax parsed above.
- RFC 9083 (RDAP JSON responses) and https://rdap.org/ as a routing front end.
