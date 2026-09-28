---
title: "Nmap and Recon Cheatsheet"
category: misc
subcategory: recon
type: cheatsheet
tags: [nmap, masscan, rustscan, port-scanning, nse, banner-grabbing, netcat, openssl, whatweb, httpx, recon, service-detection, udp-scan]
summary: "Copy-paste nmap phases, NSE scripts, masscan/rustscan combos and manual banner grabs for fast host and service recon."
related: [net-scanning-fingerprinting, net-service-enumeration-cheatsheet, net-fuzzing-cheatsheet]
---

## Host discovery

```bash
# Ping sweep a subnet (no port scan)
nmap -sn 10.10.10.0/24 -oA sweep
# ARP scan on a local segment (fast, reliable on LAN)
sudo nmap -sn -PR 10.10.10.0/24
# TCP-SYN discovery to common ports when ICMP is filtered
nmap -sn -PS22,80,443,3389,445 10.10.10.0/24
# Treat host as up, skip discovery (standard for CTF)
nmap -Pn 10.10.10.5
# List targets without scanning (sanity-check scope)
nmap -sL 10.10.10.0/24
```

## Fast full TCP sweep

```bash
# All ports, SYN scan, fast rate, no DNS (root)
sudo nmap -p- --min-rate 5000 -T4 -Pn -n -sS 10.10.10.5 -oA all-tcp
# All ports, connect scan (no root needed)
nmap -p- --min-rate 2000 -Pn -n -sT 10.10.10.5 -oA all-tcp
# Extract open ports into a comma list for the deep scan
ports=$(grep -oP '^\d+(?=/tcp\s+open)' all-tcp.nmap | paste -sd, -)
```

## Deep scan on found ports

```bash
# Version + default scripts on discovered ports only
sudo nmap -p"$ports" -sCV -Pn -n 10.10.10.5 -oA deep
# Maximum version intensity for a stubborn service
sudo nmap -p 31337 -sV --version-all 10.10.10.5
# Aggressive: scripts + version + OS + traceroute (root, noisy)
sudo nmap -A -p"$ports" 10.10.10.5 -oA aggressive
```

## UDP

```bash
# Top 100 UDP ports with version detection
sudo nmap -sU --top-ports 100 -Pn -n 10.10.10.5 -oA udp-top100
# Targeted classic UDP services
sudo nmap -sU -p 53,69,123,161,500,5353 -sV 10.10.10.5
```

## Timing and evasion

```bash
# Honest speed control (packets/sec)
sudo nmap -p- --min-rate 3000 --max-retries 2 10.10.10.5
# Slow scan to dodge rate limiting / IDS
sudo nmap -T2 --scan-delay 200ms 10.10.10.5
# Fragment packets / decoys / spoof source port
sudo nmap -f -D RND:5 --source-port 53 10.10.10.5
```

## Output formats

```bash
# All three formats at once (.nmap/.gnmap/.xml)
nmap -sCV 10.10.10.5 -oA scan
# Greppable output only
nmap -sCV 10.10.10.5 -oG scan.gnmap
# Convert XML to HTML report
xsltproc scan.xml -o scan.html
# Pull open ports from greppable output
grep -oP '\d+/open' scan.gnmap | cut -d/ -f1 | sort -un
```

## NSE scripts

```bash
# List scripts in a category
nmap --script-help "default and safe"
# HTTP enumeration
nmap -p80,443 --script "http-title,http-headers,http-methods,http-robots.txt,http-enum" 10.10.10.5
# TLS certificate + cipher enumeration
nmap -p443 --script "ssl-cert,ssl-enum-ciphers" 10.10.10.5
# SMB OS, shares, security mode, MS17-010
nmap -p445 --script "smb-os-discovery,smb-security-mode,smb-enum-shares,smb-vuln-ms17-010" 10.10.10.5
# DNS zone transfer
nmap -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.ctf 10.10.10.5
# SNMP info (UDP)
sudo nmap -sU -p161 --script "snmp-info,snmp-sysdescr,snmp-processes" 10.10.10.5
# FTP anonymous + vsftpd backdoor
nmap -p21 --script "ftp-anon,ftp-vsftpd-backdoor" -sV 10.10.10.5
# Vuln category on ONE port with a timeout (noisy, verify hits)
nmap -p443 --script vuln --script-timeout 60s 10.10.10.5
# Update the script database
sudo nmap --script-updatedb
```

## masscan

```bash
# All ports across a /16 at 10k pps, list output
sudo masscan -p1-65535 10.10.0.0/16 --rate 10000 -oL masscan.txt --wait 3
# Specific ports on a subnet
sudo masscan -p80,443,445,3389 10.10.10.0/24 --rate 5000
# Force the VPN interface if masscan picks the wrong one
sudo masscan -p1-65535 10.10.10.5 -e tun0 --rate 5000
# Turn masscan output into ip:port pairs
awk '/^open/ {print $4":"$3}' masscan.txt | sort -u
```

## rustscan

```bash
# Discover ports then hand them to nmap after --
rustscan -a 10.10.10.5 --ulimit 5000 -- -sCV -oA rust
# Scan a range/subnet
rustscan -a 10.10.10.0/24 --ulimit 5000
```

## Manual banner grabbing

```bash
# Raw banner (server speaks first)
nc -nv 10.10.10.5 31337
# HTTP request by hand
printf 'GET / HTTP/1.1\r\nHost: target.ctf\r\nConnection: close\r\n\r\n' | nc 10.10.10.5 80
# TLS service: negotiate and read the cert
openssl s_client -connect 10.10.10.5:443 -servername target.ctf
# STARTTLS service (smtp/imap/pop3/ftp/ldap)
openssl s_client -connect 10.10.10.5:25 -starttls smtp
# Timeout-wrapped multi-port grab
for p in 21 22 25 80 110 143 443 3306 8080; do echo "== $p"; timeout 3 nc -nv 10.10.10.5 "$p" </dev/null; done
```

## Web fingerprinting

```bash
# Identify CMS/framework/server
whatweb -a 3 http://10.10.10.5
# Probe a host list: status, title, tech, length
httpx -l hosts.txt -ports 80,443,8080,8443 -title -tech-detect -status-code -content-length
# Screenshot a batch of hosts
httpx -l hosts.txt -screenshot -srd shots/
# Nuclei known-exposure scan
nuclei -u http://10.10.10.5 -severity medium,high,critical
# Favicon hash (mmh3) for product ID
curl -s http://10.10.10.5/favicon.ico | python3 -c "import sys,mmh3,base64;print(mmh3.hash(base64.encodebytes(sys.stdin.buffer.read())))"
```

## Service-specific version checks

```bash
# SSH algorithm/version audit
ssh-audit 10.10.10.5
# TLS config, ciphers, cert, vulns
testssl.sh https://10.10.10.5
# SMB dialects and signing
netexec smb 10.10.10.5
# HTTP methods (look for PUT/DELETE/TRACE)
curl -sX OPTIONS http://10.10.10.5/ -i | grep -i allow
```

## /etc/hosts workflow

```bash
# Add discovered vhosts so tools resolve them
printf '10.10.10.5\ttarget.ctf dev.target.ctf admin.target.ctf\n' | sudo tee -a /etc/hosts
# Names from the TLS cert SAN
openssl s_client -connect 10.10.10.5:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 'Alternative Name'
```

## Quick triage loop

```bash
# One-liner: full sweep then deep scan the open ports
sudo nmap -p- --min-rate 4000 -Pn -n 10.10.10.5 -oG - | grep -oP '\d+(?=/open)' | paste -sd, - | \
  xargs -I{} sudo nmap -p{} -sCV -Pn -n 10.10.10.5 -oA deep
```
