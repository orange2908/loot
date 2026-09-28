---
title: "Cheatsheet - PCAP Correlation for Sherlocks (tshark, UTC, attack reconstruction)"
category: sherlocks
subcategory: pcap
type: cheatsheet
tags: [pcap, pcapng, tshark, wireshark, capinfos, tds, mssql, xp-cmdshell, reverse-shell, netcat, nmap, port-scan, arp, clock-skew, utc, timeline, dfir, sherlock, network-forensics]
summary: "tshark one-liners that turn a Sherlock pcap into an attack timeline in UTC: conversations, scans, TDS/SQL queries, reverse shells, HTTP downloads, SMB, and host-vs-pcap clock skew."
tools: [tshark, capinfos, wireshark, zeek]
related: [sherlock-triage, windows-evtx-hunting, tshark-wireshark-cheatsheet]
---

## Always force UTC

```sh
# capinfos and tshark print local time unless TZ=UTC; HTB answers are UTC
TZ=UTC capinfos -a -e cap.pcapng
TZ=UTC tshark -r cap.pcapng -t ud -c 5
# if tshark says "You don't have permission to read the file" on extracted evidence, copy it elsewhere first
cp cap.pcapng /tmp/t.pcapng
```

## Who talks to whom

```sh
tshark -r cap.pcapng -q -z conv,ip | head -25
tshark -r cap.pcapng -q -z endpoints,ip
# ports each host serves
tshark -r cap.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==1' -T fields -e ip.src -e tcp.srcport | sort | uniq -c | sort -rn | head
# name the hosts: DNS answers, NBNS, Kerberos realms, SMB host names
tshark -r cap.pcapng -Y 'dns.flags.response==1' -T fields -e dns.qry.name -e dns.a | sort -u
tshark -r cap.pcapng -Y 'kerberos' -T fields -e kerberos.realm -e kerberos.CNameString -e kerberos.SNameString | sort -u
```

## Recon: ARP sweep and port scan (earliest malicious activity)

```sh
# ARP who-has from the attacker
TZ=UTC tshark -r cap.pcapng -t ud -Y 'arp.opcode==1' -T fields -e _ws.col.Time -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 | head
# SYN scan: many bare SYNs, Win=1024, same source port (nmap -sS signature)
TZ=UTC tshark -r cap.pcapng -t ud -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.window_size_value==1024' -T fields -e _ws.col.Time -e ip.src -e ip.dst -e tcp.dstport | head
# first packet between attacker and target
TZ=UTC tshark -r cap.pcapng -t ud -Y 'ip.addr==A && ip.addr==B' -T fields -e _ws.col.Time -e _ws.col.Protocol -e _ws.col.Info | head -3
```

## MSSQL / TDS

```sh
# every SQL batch: brute-force probes, xp_cmdshell, enable_xp_cmdshell
TZ=UTC tshark -r cap.pcapng -t ud -Y 'tds.query' -T fields -e _ws.col.Time -e ip.src -e tds.query
# TDS packet types per second (18=prelogin, 16=login7, 1=SQL batch)
TZ=UTC tshark -r cap.pcapng -t ud -Y 'tds && ip.src==ATTACKER' -T fields -e _ws.col.Time -e tds.type | cut -c12-19,30- | uniq -c
# force the dissector if SQL runs on a non-standard port
tshark -r cap.pcapng -d tcp.port==14330,tds -Y tds.query -T fields -e tds.query
```

## Downloads (certutil / iwr / python http.server)

```sh
TZ=UTC tshark -r cap.pcapng -t ud -Y 'http.request' -T fields -e _ws.col.Time -e ip.src -e http.host -e http.request.uri -e http.user_agent
# certutil user agent: "Microsoft-CryptoAPI/10.0" (plus a CertUtil URL Agent probe)
tshark -r cap.pcapng -Y 'http.user_agent contains "CryptoAPI" || http.user_agent contains "CertUtil"' -T fields -e http.host -e http.request.uri
# carve the transferred files
tshark -r cap.pcapng --export-objects http,./http_objects && sha256sum http_objects/*
```

## Reverse shells

```sh
# the victim connecting OUT to the attacker's listener
TZ=UTC tshark -r cap.pcapng -t ud -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==VICTIM && ip.dst==ATTACKER' -T fields -e _ws.col.Time -e tcp.dstport
# the shell banner = the moment the attacker has an interactive shell
TZ=UTC tshark -r cap.pcapng -t ud -Y 'tcp.port==4444 && tcp.len>0' -T fields -e _ws.col.Time -e ip.src -e data.text -o data.show_as_text:TRUE | head
# whole session as text
tshark -r cap.pcapng -q -z follow,tcp,ascii,$(tshark -r cap.pcapng -Y 'tcp.port==4444' -T fields -e tcp.stream | head -1)
# find banners anywhere
tshark -r cap.pcapng -Y 'frame contains "Microsoft Windows [Version"' -T fields -e frame.time_epoch -e tcp.stream
```

## SMB / exfil

```sh
tshark -r cap.pcapng -Y 'smb2.cmd==3' -T fields -e ip.src -e ip.dst -e smb2.tree | sort -u
tshark -r cap.pcapng -Y 'smb2.filename' -T fields -e _ws.col.Time -e ip.src -e smb2.filename | sort -u
tshark -r cap.pcapng -Y 'ntlmssp.messagetype==3' -T fields -e ntlmssp.auth.domain -e ntlmssp.auth.username -e ntlmssp.auth.hostname
tshark -r cap.pcapng --export-objects smb,./smb_objects
```

## Clock skew check (important for timestamp answers)

```sh
# pick one event visible in both places, e.g. xp_cmdshell 'dir C:\'
# host 4688 cmd.exe /c dir C:\ = 19:27:26 ; TDS query in pcap = 19:27:24 -> ~2s skew
```

- HTB graders sometimes take times from the pcap and sometimes from the host logs. If one is rejected, submit the other.
- In SaSync the pcap times were the accepted answers for the first command, the reverse shell and the earliest activity.

## Epoch to UTC helper

```sh
tshark -r cap.pcapng -T fields -e frame.time_epoch -e ip.dst | while read t d; do echo "$(date -u -d @${t%.*} '+%F %T') $d"; done
```
