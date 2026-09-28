---
title: "Port Scanning and Service Fingerprinting - Doing Recon Properly"
category: misc
subcategory: recon
type: technique
tags: [nmap, masscan, rustscan, port-scanning, service-detection, banner-grabbing, nse, whatweb, httpx, netcat, udp-scan, fingerprinting, recon, version-detection, enumeration]
difficulty: easy
summary: "Two-stage scanning: fast full-range sweep to find ports, then targeted -sCV plus NSE on exactly those ports, then per-service fingerprinting."
when_to_use:
  - "A box/IP has just been handed to you and you have no other information"
  - "You found a service but do not know the product or version"
  - "Your first nmap finished in 3 seconds and found nothing -- you scanned the default 1000 ports only"
  - "A challenge hints at a service on a high port (>10000) or on UDP"
tools: [nmap, masscan, rustscan, netcat, openssl, whatweb, httpx, nuclei]
related: [net-service-enumeration-cheatsheet, net-nmap-and-recon-cheatsheet, net-content-discovery]
---

## TL;DR

Never run one scan. Run a **fast full-range discovery scan** to learn *which* ports are open,
then a **slow, deep scan** against only those ports for version/script detection, then
**per-service fingerprinting** with the right tool for each protocol. Nmap's default is the
top 1000 TCP ports -- CTF boxes routinely hide the interesting service on 8443, 31337 or UDP 161.

## Recognise it

- You have an IP and nothing else.
- `nmap 10.10.10.5` returned "22/tcp open ssh, 80/tcp open http" and the box is rated hard -- there is more.
- The web app is a decoy and the real entry point is an unauthenticated service on a high port.
- A service answers but `nmap` prints `tcpwrapped` or a bare `open` with no version.

## Attack

### Phase 0 -- decide about host discovery

```bash
# Ping sweep a /24 to find live hosts (no port scan, ARP on a local segment)
nmap -sn 10.10.10.0/24 -oA sweep

# Skip host discovery entirely -- required when ICMP is filtered (most HTB/CTF boxes)
nmap -Pn 10.10.10.5

# Discovery using TCP SYN to common ports instead of ICMP, for filtered networks
nmap -sn -PS22,80,443,3389 10.10.10.0/24
```

Rule of thumb for CTF: **always add `-Pn`** once you know the host is up. It saves time and
avoids "host seems down" false negatives.

### Phase 1 -- fast full TCP range

```bash
# All 65535 TCP ports, SYN scan, aggressive packet rate, no DNS, no version detection
sudo nmap -p- --min-rate 5000 -T4 -Pn -n -sS 10.10.10.5 -oA nmap/all-tcp

# Same idea without root: connect() scan, slower but works unprivileged
nmap -p- --min-rate 2000 -Pn -n -sT 10.10.10.5 -oA nmap/all-tcp
```

`--min-rate` is the honest speed knob; `-T4` only sets timeouts and parallelism defaults.
On a flaky VPN drop to `--min-rate 1000 -T3` -- a fast scan that misses ports is worse than a slow one.

Extract the port list for phase 2:

```bash
# Pull the open port numbers out of the greppable output into a comma list
ports=$(grep -oP '^\d+(?=/tcp\s+open)' nmap/all-tcp.nmap | paste -sd, -)
echo "$ports"
```

### Phase 2 -- deep scan on the found ports only

```bash
# Version detection + default NSE scripts + traceroute, only on the discovered ports
sudo nmap -p"$ports" -sCV -Pn -n --version-all 10.10.10.5 -oA nmap/deep

# If a service is stubborn, raise version intensity and show the probe responses
sudo nmap -p 31337 -sV --version-intensity 9 --script banner 10.10.10.5
```

- `-sC` = `--script=default` (safe, discovery-oriented scripts).
- `-sV` = version probes. `--version-all` is `--version-intensity 9`.
- `-A` = `-sC -sV -O --traceroute`; fine, but `-O` needs root and is noisy/unreliable in labs.

### Phase 3 -- UDP

UDP is slow because closed ports are silent. Scan the top ports, not all of them.

```bash
# Top 100 UDP ports with version detection -- the pragmatic default
sudo nmap -sU --top-ports 100 -Pn -n 10.10.10.5 -oA nmap/udp-top100

# Targeted UDP check for the classic four when time is short
sudo nmap -sU -p 53,69,123,161 -sV 10.10.10.5
```

The UDP ports that actually matter in CTF: 53 (DNS), 69 (TFTP), 123 (NTP), 161 (SNMP),
137 (NetBIOS name), 500 (IKE), 1434 (MSSQL browser), 5353 (mDNS).

### Phase 4 -- masscan + nmap combo (large ranges)

masscan finds ports fast across a whole network; nmap then identifies them.

```bash
# Scan an entire /16 for one port set at 10k packets/sec, list output
sudo masscan -p1-65535 10.10.0.0/16 --rate 10000 -oL masscan.txt --wait 3

# Turn masscan output into "ip:port" pairs
awk '/^open/ {print $4":"$3}' masscan.txt | sort -u > targets.txt

# Feed the unique hosts back into nmap for service detection
cut -d: -f1 targets.txt | sort -u > hosts.txt
sudo nmap -iL hosts.txt -p"$(cut -d: -f2 targets.txt | sort -un | paste -sd, -)" -sCV -oA nmap/mass-deep
```

`--wait 3` keeps masscan listening for late replies instead of exiting immediately.
masscan needs root and uses its own TCP stack -- on a tun/VPN interface add `--adapter-ip`
or `-e tun0` if it picks the wrong interface.

### Phase 5 -- rustscan shortcut

```bash
# Rustscan finds open ports then hands them to nmap after the -- separator
rustscan -a 10.10.10.5 --ulimit 5000 -- -sCV -oA nmap/rust
```

Convenient, but on a slow VPN it produces false negatives; `nmap -p-` remains the reference.

### NSE scripts worth running

```bash
# Enumerate HTTP: common paths, titles, methods, headers, robots
nmap -p80,443 --script "http-title,http-headers,http-methods,http-robots.txt,http-enum" 10.10.10.5

# TLS certificate details -- names in the SAN field give you vhosts and internal hostnames
nmap -p443 --script ssl-cert,ssl-enum-ciphers 10.10.10.5

# SMB: OS, shares, security mode, and the MS17-010 check
nmap -p445 --script "smb-os-discovery,smb-security-mode,smb-enum-shares,smb2-security-mode,smb-vuln-ms17-010" 10.10.10.5

# DNS: attempt a zone transfer against an authoritative server
nmap -p53 --script dns-nsid,dns-zone-transfer --script-args dns-zone-transfer.domain=target.ctf 10.10.10.5

# SNMP with a community string list
nmap -sU -p161 --script "snmp-info,snmp-sysdescr,snmp-interfaces,snmp-win32-services" 10.10.10.5

# FTP: anonymous login and the classic vsftpd backdoor check
nmap -p21 --script "ftp-anon,ftp-syst,ftp-vsftpd-backdoor" 10.10.10.5

# Show every script in a category before running it
nmap --script-help "default and safe"
```

Caveats on `--script vuln`: it is slow, noisy, and produces false positives; several scripts
in that category are intrusive. Run it late, on a single port, and verify every hit by hand.

```bash
# Vuln category against one service only, with a time cap
nmap -p443 --script vuln --script-timeout 60s 10.10.10.5
```

### Phase 6 -- manual banner grabbing

When nmap says `tcpwrapped` or gives no version, talk to the port yourself.

```bash
# Raw banner: connect and wait for the server to speak first
nc -nv 10.10.10.5 31337

# Send an HTTP request by hand to see raw headers
printf 'GET / HTTP/1.1\r\nHost: target.ctf\r\nConnection: close\r\n\r\n' | nc 10.10.10.5 80

# TLS-wrapped service: negotiate then interact, and print the cert
openssl s_client -connect 10.10.10.5:443 -servername target.ctf

# STARTTLS services (smtp/imap/pop3/ftp/ldap) need the protocol flag
openssl s_client -connect 10.10.10.5:25 -starttls smtp

# Timeout-wrapped grab across many ports in one line
for p in 22 80 443 8080 8443; do echo "== $p"; timeout 3 nc -nv 10.10.10.5 "$p" </dev/null; done
```

### Phase 7 -- web stack fingerprinting

```bash
# Identify CMS, framework, server, JS libs and versions
whatweb -a 3 http://10.10.10.5

# Probe a list of hosts/ports, print status, title, tech and content length
httpx -l hosts.txt -ports 80,443,8080,8443 -title -tech-detect -status-code -content-length

# Template scan for known exposures once you know the stack
nuclei -u http://10.10.10.5 -severity medium,high,critical

# Favicon hash -- often uniquely identifies a product
curl -s http://10.10.10.5/favicon.ico | python3 -c "import sys,mmh3,base64;print(mmh3.hash(base64.encodebytes(sys.stdin.buffer.read())))"
```

## Code

A small helper that turns nmap's XML into a per-host, per-port checklist so nothing gets
forgotten. Works on any `-oX`/`-oA` output.

```python
#!/usr/bin/env python3
"""Parse nmap XML into a per-service next-step checklist.

Usage:
    python3 nmap_triage.py nmap/deep.xml
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

NEXT_STEPS: dict[str, list[str]] = {
    "ftp": ["anonymous login", "ftp-anon NSE", "wget -r ftp://HOST/"],
    "ssh": ["version -> CVE check", "try found keys", "ssh-audit"],
    "smtp": ["VRFY/RCPT user enum", "open relay test"],
    "domain": ["AXFR zone transfer", "TXT/SRV records"],
    "http": ["whatweb", "ffuf directories", "vhost fuzz", "check /robots.txt"],
    "https": ["ssl-cert SAN names", "whatweb", "ffuf directories"],
    "pop3": ["login with found creds", "LIST/RETR"],
    "rpcbind": ["rpcinfo -p", "showmount -e"],
    "netbios-ssn": ["smbclient -L -N", "netexec smb --shares"],
    "microsoft-ds": ["null session", "rid brute", "smbmap"],
    "ldap": ["anonymous bind", "ldapsearch namingcontexts"],
    "mysql": ["root blank password", "version -> CVE"],
    "rdp": ["cert name", "credential spray (careful: lockout)"],
    "postgresql": ["postgres:postgres", "COPY FROM PROGRAM"],
    "redis": ["INFO", "CONFIG GET dir", "unauth write"],
    "mongod": ["no-auth connect", "show dbs"],
    "elasticsearch": ["/_cat/indices?v", "/_search?pretty"],
    "winrm": ["evil-winrm with creds"],
}


def parse(path: str) -> list[tuple[str, str, str, str, str]]:
    """Return (host, port, proto, service, product-version) tuples for open ports."""
    rows: list[tuple[str, str, str, str, str]] = []
    root = ET.parse(path).getroot()
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr", "?")
        for port in host.iterfind("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            name = svc.get("name", "unknown") if svc is not None else "unknown"
            product = ""
            if svc is not None:
                product = " ".join(
                    x for x in (svc.get("product"), svc.get("version"), svc.get("extrainfo")) if x
                )
            rows.append((addr, port.get("portid", "?"), port.get("protocol", "tcp"), name, product))
    return rows


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    rows = parse(argv[1])
    if not rows:
        print("no open ports found in", argv[1])
        return 0
    current = None
    for host, port, proto, name, product in rows:
        if host != current:
            print(f"\n=== {host} ===")
            current = host
        print(f"{port:>6}/{proto}  {name:<16} {product}")
        for step in NEXT_STEPS.get(name, ["manual banner grab: nc -nv HOST PORT"]):
            print(f"         [ ] {step}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Default 1000 ports.** `nmap host` is not a scan, it is a guess. Always `-p-` eventually.
- **`filtered` vs `closed`.** `closed` = RST received (host is up, nothing listening).
  `filtered` = no answer (firewall dropped it). A wall of `filtered` usually means your scan
  is being rate-limited -- slow down and rescan.
- **Rate limiting / SYN cookies.** If results differ between runs, drop `--min-rate` and rerun.
  Confirm a port with `nc` before believing a single nmap line.
- **`tcpwrapped`.** Nmap completed the handshake but the service closed before speaking. Usually
  means an access-control wrapper or a scan-rate defence. Retry slowly and grab the banner manually.
- **Load balancers.** Different scans hitting different backends produce inconsistent results.
  Compare TTLs and TLS certificates.
- **`-sV` on a fragile service** can crash CTF services written in Python. If a service dies,
  rescan without `-sV` and interact by hand.
- **Hostnames matter.** Many boxes only serve the real vhost when the `Host:` header matches.
  Take names out of the TLS certificate and HTTP redirects, put them in `/etc/hosts`, rescan HTTP.
- **IPv6.** `nmap -6` is a separate scan; some boxes expose extra services on IPv6 only.
- **Don't scan out of scope.** In attack-defense and hosted CTFs, scanning the wrong /24 gets you banned.

## Tools

- `nmap` -- reference scanner; NSE for protocol-aware enumeration.
- `masscan` -- internet-scale SYN sweep; pair with nmap.
- `rustscan` -- fast port discovery front-end for nmap.
- `netcat` / `socat` / `openssl s_client` -- manual banner grabbing.
- `whatweb`, `httpx`, `nuclei` -- HTTP fingerprinting and known-exposure checks.
- `ssh-audit`, `testssl.sh` -- protocol-specific deep fingerprinting.

## References

- Nmap reference guide and the NSE script documentation shipped with the tool (`man nmap`, `nmap --script-help`).
- `man masscan` for the packet-rate and adapter options.
- RFC 793 (TCP) for what SYN/RST/no-reply actually mean in scan results.
