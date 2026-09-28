---
title: "Tool - nmap"
category: misc
subcategory: recon
type: tool
tags: [nmap, port-scan, service-detection, nse, scripts, recon, enumeration, udp, syn-scan, version-detection, network, host-discovery, masscan]
summary: "Port scanning and service fingerprinting, plus the NSE script engine for protocol-specific enumeration."
related: [common-ports-services, remote-service, web-triage]
---

## What it is

nmap discovers which ports are open on a host, what service is behind each, and - through the Nmap Scripting Engine (NSE) - runs protocol-specific checks: anonymous FTP, SMB shares, DNS zone transfers, SSL certificate details, default credentials and known vulnerabilities.

In jeopardy CTF you usually already know the port. nmap matters for boot2root machines, A/D competitions and any challenge that hands you a network range.

## Install

```sh
# Debian/Ubuntu/Kali
sudo apt install nmap
# macOS
brew install nmap
# verify
nmap --version
nmap --script-updatedb          # refresh the NSE database
```

## The invocations that matter

```sh
H=10.10.10.10

# 1. the two-stage scan: fast full sweep, then deep on what is open
sudo nmap -p- --min-rate 5000 -T4 -Pn -n -oA all "$H"
PORTS=$(grep -oP '^\d+(?=/tcp\s+open)' all.nmap | paste -sd, -)
sudo nmap -sCV -p "$PORTS" -oA deep "$H"

# 2. the default quick scan (top 1000 ports, scripts + versions)
sudo nmap -sCV "$H"

# 3. UDP (slow - only the top ports are worth it)
sudo nmap -sU --top-ports 20 -T4 -oA udp "$H"

# 4. skip host discovery when ICMP is blocked (essential on CTF boxes)
sudo nmap -Pn "$H"

# 5. aggressive: version, scripts, OS detection, traceroute
sudo nmap -A -T4 "$H"

# 6. category-based NSE scans
sudo nmap --script=default,safe,vuln -p "$PORTS" "$H"
sudo nmap --script=discovery -p 161 -sU "$H"

# 7. targeted NSE for one protocol
sudo nmap --script='http-*' -p 80,443 "$H"
sudo nmap --script='smb-enum-shares,smb-enum-users,smb-os-discovery' -p 445 "$H"
sudo nmap --script='ssl-cert,ssl-enum-ciphers' -p 443 "$H"
sudo nmap --script='dns-zone-transfer' --script-args dns-zone-transfer.domain=example.ctf -p 53 "$H"
sudo nmap --script='ftp-anon,ftp-syst' -p 21 "$H"
sudo nmap --script='mysql-empty-password,mysql-info' -p 3306 "$H"
sudo nmap --script='redis-info' -p 6379 "$H"

# 8. scan a range / discover live hosts
nmap -sn 10.10.10.0/24                    # ping sweep, no port scan
nmap -p 22,80,443 10.10.10.0/24 --open

# 9. output formats (always use -oA; you will want to grep later)
nmap -sCV "$H" -oA scan                   # writes scan.nmap, scan.xml, scan.gnmap
grep -E 'open' scan.gnmap
xsltproc scan.xml -o scan.html

# 10. very fast alternative for the initial sweep on a large range
masscan -p1-65535 "$H" --rate 10000 -oL masscan.txt
```

Scan-type flags:

| Flag | Meaning |
|---|---|
| `-sS` | SYN ("stealth") scan - the default when root; fast and reliable |
| `-sT` | full TCP connect - used automatically without root, and required through proxychains |
| `-sU` | UDP |
| `-sN`/`-sF`/`-sX` | null/FIN/Xmas - occasionally bypass naive filters |
| `-sV` | service/version detection (`--version-intensity 0-9`) |
| `-sC` | run the default NSE scripts (same as `--script=default`) |
| `-O` | OS detection |
| `-A` | `-sV -sC -O --traceroute` |
| `-Pn` | skip host discovery (assume up) |
| `-n` | no DNS resolution (much faster) |
| `-p-` | all 65535 ports |
| `-F` | fast: top 100 ports |
| `--top-ports N` | the N most common |
| `-T0..-T5` | timing template; `-T4` is the CTF default |
| `--min-rate N` | packets per second floor - the real speed knob |
| `--open` | only show open ports |
| `-v`/`-vv` | progress output while it runs |
| `--reason` | why nmap decided a port's state |
| `-6` | IPv6 |
| `-e iface` / `-S ip` | pick an interface / spoof a source |

Finding scripts:
```sh
ls /usr/share/nmap/scripts/ | grep -i smb
nmap --script-help='http-shellshock'
grep -l 'categories.*vuln' /usr/share/nmap/scripts/*.nse | head
```

## Gotchas

- **`-sS`, `-sU` and `-O` need root.** Without it nmap silently falls back to `-sT`, which is slower and noisier.
- **`-Pn` is almost always needed in CTF**: challenge hosts commonly drop ICMP, and without `-Pn` nmap declares them down and scans nothing.
- `--min-rate` is what actually controls speed; `-T4` alone is not enough for a `-p-` scan. `--min-rate 5000` turns a 20-minute scan into 30 seconds on a LAN.
- UDP scanning is genuinely slow and unreliable (no response is ambiguous). Scan the top 20 and move on unless the challenge points at UDP.
- Version detection can crash fragile CTF services. If a challenge container dies when you scan it, that is why - re-read the rules about scanning.
- `--script=vuln` includes scripts that actively exploit; on a shared CTF instance that can be disruptive and is sometimes against the rules.
- nmap's "filtered" means no response - a firewall, not necessarily a closed port.
- Scanning through a SOCKS proxy requires `-sT -Pn` under `proxychains`; SYN scans do not work over a proxy.
- In a jeopardy CTF, port-scanning the scoreboard or unrelated infrastructure is usually explicitly forbidden. Scan only what the challenge gives you.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Very large ranges | `masscan` (fast discovery), then nmap for detail |
| A single port check | `nc -vz host port`, `/dev/tcp/host/port` in bash |
| Service interaction after discovery | `ctfbrain search remote-service` |
| Web-specific enumeration | `ffuf`, `whatweb`, `nuclei` |
| Through a pivot/proxy | `proxychains nmap -sT -Pn`, or `chisel`+`nmap` |
| No nmap available on target | a bash loop over `/dev/tcp`, or `netcat -z` |
| Service fingerprinting only | `nc host port` and read the banner; `amap` |
