---
title: "tshark and Wireshark Cheatsheet - Filters, Fields and Extraction"
category: forensics
subcategory: network
type: cheatsheet
tags: [tshark, wireshark, pcap, pcapng, display-filter, bpf, capinfos, editcap, mergecap, tcpdump, tcpflow, ngrep, zeek, networkminer, export-objects, follow-stream, decode-as, tls-decryption, network-forensics, dfir]
summary: "Reading, filtering, extracting: tshark invocations, 120-plus display filters across 30 protocols, -T fields recipes, export objects, TLS decryption and BPF equivalents."
tools: [tshark, wireshark, capinfos, editcap, mergecap, tcpdump, tcpflow, ngrep, zeek, networkminer, foremost]
related: [network-pcap-triage, network-extract-files-creds, network-tls-decryption, network-covert-channels, network-usb-hid]
---

Two filter languages: **capture filters** are BPF (`-f`, tcpdump syntax, applied before capture);
**display filters** are Wireshark syntax (`-Y`, applied after dissection). `-Y` is what you want 99%
of the time on a file. `-2` enables a two-pass analysis so `-Y` can use reassembly-dependent fields.

## Reading and converting files

```sh
# shape of the capture: packet count, duration, first/last timestamp, link type, hashes
capinfos -A capture.pcap
# convert pcapng to classic pcap (many old tools refuse pcapng)
editcap -F pcap capture.pcapng capture.pcap
# split a huge capture into 100k-packet chunks so tools stop OOMing
editcap -c 100000 capture.pcap chunk.pcap
# slice out a time window (inclusive start, exclusive stop), UTC or local per your TZ
editcap -A "2024-05-01 10:00:00" -B "2024-05-01 10:05:00" capture.pcap window.pcap
# deduplicate packets repeated within a 0.1s window (span-port double-capture artefact)
editcap -d -D 50 capture.pcap dedup.pcap
# merge captures in chronological order (-a concatenates instead)
mergecap -w merged.pcap part1.pcap part2.pcap part3.pcap
# write only the packets matching a display filter to a new file
tshark -r capture.pcap -Y 'tcp.stream eq 7' -w stream7.pcap
```

## Statistics (-z taps)

```sh
# protocol hierarchy with byte counts - your roadmap, always run this first
tshark -r capture.pcap -q -z io,phs
# TCP conversations ranked; swap tcp for udp, ip, eth, ipv6
tshark -r capture.pcap -q -z conv,tcp
# endpoint totals, best for spotting the single external IP that matters
tshark -r capture.pcap -q -z endpoints,ip
# bytes per second in 10-second buckets - shows the exfil burst
tshark -r capture.pcap -q -z io,stat,10
# io,stat with columns: packets, then only DNS, then only TLS, per 60s bucket
tshark -r capture.pcap -q -z 'io,stat,60,COUNT(frame)frame,COUNT(dns)dns,COUNT(tls)tls'
# every HTTP request/response pair with response codes, grouped by host
tshark -r capture.pcap -q -z http,tree
# DNS query/response statistics including rcode distribution
tshark -r capture.pcap -q -z dns,tree
# expert info (warnings, errors, retransmissions, malformed packets)
tshark -r capture.pcap -q -z expert
# flow sequence diagram as text - good for small captures
tshark -r capture.pcap -q -z flow,tcp,network
# VoIP call list with durations
tshark -r capture.pcap -q -z sip,stat
```

## Display filter syntax

```sh
# comparison operators: eq == , ne != , gt > , lt < , ge >= , le <=
tshark -r capture.pcap -Y 'frame.len > 1000 && ip.ttl <= 64'
# logical: and && , or || , not ! ; always quote so the shell keeps them
tshark -r capture.pcap -Y 'http && !(ip.addr == 10.0.0.1)'
# "contains" does a raw substring match on the field bytes
tshark -r capture.pcap -Y 'http.user_agent contains "curl"'
# "matches" is a PCRE regex, case-insensitive by default
tshark -r capture.pcap -Y 'http.request.uri matches "\\.(php|asp|jsp)\\?"'
# membership sets are far cheaper than a chain of ||
tshark -r capture.pcap -Y 'tcp.port in {80 443 8080 8443}'
# byte slices: field[offset:length] compared against a hex byte string
tshark -r capture.pcap -Y 'tcp.payload[0:4] == 50:4b:03:04'
# frame contains searches the whole raw packet, dissector-independent
tshark -r capture.pcap -Y 'frame contains "flag{"'
# frame matches applies a regex to the whole raw packet
tshark -r capture.pcap -Y 'frame matches "[a-zA-Z0-9]{8}\\{.{4,60}\\}"'
# a bare field name is an existence test
tshark -r capture.pcap -Y 'http.authorization'
```

## Filters - ethernet, arp, ip, ipv6, icmp

| Display filter | Matches |
|---|---|
| `eth.addr == 00:11:22:33:44:55` | Either MAC equals |
| `eth.type == 0x0806` | ARP frames by ethertype |
| `vlan.id == 20` | 802.1Q VLAN tag |
| `arp.opcode == 1` | ARP requests (2 = replies) |
| `arp.src.proto_ipv4 == 10.0.0.1` | ARP sender IP |
| `arp.duplicate-address-detected` | ARP spoofing / poisoning |
| `ip.addr == 10.0.0.5` | Either IPv4 address |
| `ip.src == 10.0.0.0/24` | Source in a CIDR block |
| `ip.ttl < 32` | Low TTL, traceroute or spoofing |
| `ip.flags.mf == 1 or ip.frag_offset > 0` | Fragmented IPv4 |
| `ip.id == 0x1337` | Fixed IP ID, a covert-channel tell |
| `ipv6.addr == 2001:db8::1` | Either IPv6 address |
| `ipv6.nxt == 58` | ICMPv6 next header |
| `icmp.type == 8` | Echo request (0 = reply) |
| `icmp.type == 3 && icmp.code == 3` | Port unreachable |
| `icmp && data.len > 48` | Oversized ICMP payload = tunnel |
| `icmp.resp_to` | Reply matched to its request frame |

## Filters - tcp and udp

| Display filter | Matches |
|---|---|
| `tcp.port == 4444` | Either TCP port |
| `tcp.flags == 0x002` | Pure SYN (scan detection) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 1` | SYN/ACK, the port was open |
| `tcp.flags.reset == 1` | RST, closed port or torn connection |
| `tcp.flags.fin == 1 && tcp.flags.ack == 0` | FIN scan |
| `tcp.flags == 0x000` | NULL scan |
| `tcp.stream eq 3` | One whole TCP conversation |
| `tcp.analysis.retransmission` | Retransmits |
| `tcp.analysis.zero_window` | Receiver stalled |
| `tcp.analysis.flags` | Any of Wireshark's TCP anomalies |
| `tcp.len > 0` | Segments carrying payload only |
| `tcp.time_delta > 5` | Long gaps, beaconing or interactive shell |
| `tcp.payload contains 50:4b:03:04` | ZIP magic inside a TCP stream |
| `udp.port == 53` | Either UDP port |
| `udp.stream eq 0` | One UDP "conversation" |

## Filters - dns, dhcp, ntp, snmp

| Display filter | Matches |
|---|---|
| `dns.flags.response == 0` | Queries only |
| `dns.qry.name == "evil.com"` | Exact queried name |
| `dns.qry.name contains "exfil"` | Substring in the queried name |
| `dns.qry.name.len > 50` | Long labels = DNS tunnelling |
| `dns.qry.type == 16` | TXT lookups (16=TXT, 1=A, 28=AAAA, 5=CNAME) |
| `dns.count.answers > 4` | Many answers, fast-flux |
| `dns.flags.rcode == 3` | NXDOMAIN, DGA behaviour |
| `dns.a == 127.0.0.1` | Answer pointing at loopback |
| `dns.txt` | Any TXT record content |
| `dhcp.option.dhcp == 3` | DHCP Request (1=Discover, 5=ACK) |
| `dhcp.option.hostname` | Client hostname, names the machine |
| `dhcp.option.requested_ip_address == 10.0.0.9` | Requested lease address |
| `ntp.flags.mode == 3` | NTP client requests (4 = server) |
| `snmp.community == "public"` | Cleartext SNMP community string |

## Filters - http, http2, quic, tls

| Display filter | Matches |
|---|---|
| `http.request.method == "POST"` | POST requests |
| `http.request.uri contains "../"` | Path traversal attempt |
| `http.request.full_uri matches "\\.(zip\|exe\|ps1)$"` | Downloads of interest |
| `http.host == "c2.example.net"` | Host header |
| `http.user_agent contains "python-requests"` | Scripted client |
| `http.authorization` | Basic/Bearer credentials in a request |
| `http.cookie contains "session"` | Session cookies |
| `http.response.code >= 400` | Errors only |
| `http.content_type contains "octet-stream"` | Binary downloads |
| `http.file_data contains "flag{"` | Flag inside a reassembled body |
| `urlencoded-form` | Any form-encoded POST body |
| `http2.type == 1` | HTTP/2 HEADERS frames |
| `http2.header.value contains "api"` | Decoded HPACK header values |
| `http2.streamid == 5` | One HTTP/2 stream |
| `quic` | Any QUIC packet |
| `quic.long.packet_type == 0` | QUIC Initial packets |
| `tls.handshake.type == 1` | ClientHello (2 = ServerHello, 11 = Certificate) |
| `tls.handshake.extensions_server_name == "cdn.example.com"` | SNI, the hostname despite encryption |
| `tls.handshake.ciphersuite == 0x1301` | Negotiated cipher suite |
| `tls.handshake.certificate` | Certificates on the wire (export them) |
| `tls.app_data` | Encrypted application data records |

## Filters - ftp, mail, smb, kerberos, ldap

| Display filter | Matches |
|---|---|
| `ftp.request.command == "USER"` | FTP username (PASS gives the password) |
| `ftp.response.code == 230` | Successful FTP login |
| `ftp-data` | The FTP data channel carrying the file |
| `smtp.req.command == "AUTH"` | SMTP AUTH, base64 creds follow |
| `smtp.data.fragment` | Reassembled message body / attachments |
| `imap.request contains "LOGIN"` | IMAP cleartext login |
| `pop.request.command == "PASS"` | POP3 cleartext password |
| `smb2.cmd == 5` | SMB2 Create (file open) |
| `smb2.filename contains "flag"` | SMB2 filename |
| `smb2.cmd == 8` | SMB2 Read (9 = Write) |
| `ntlmssp.messagetype == 0x00000003` | NTLMSSP_AUTH, contains the NTLMv2 response |
| `ntlmssp.auth.username` | Username in the NTLM authenticate blob |
| `ntlmssp.ntlmserverchallenge` | Server challenge, needed to crack NTLMv2 |
| `kerberos.msg_type == 10` | AS-REQ (11 = AS-REP, 12 = TGS-REQ, 13 = TGS-REP) |
| `kerberos.CNameString` | Principal names, enumerates users |
| `kerberos.cipher` | Encrypted part, crackable with hashcat |
| `ldap.messageID` | Any LDAP operation |
| `ldap.simple` | LDAP simple bind password in cleartext |

## Filters - voip, iot, industrial, chat and remote access

| Display filter | Matches |
|---|---|
| `sip.Method == "INVITE"` | Call setup |
| `sip.From contains "1001"` | Caller identity |
| `rtp.p_type == 0` | G.711 u-law audio payload |
| `rtp.ssrc == 0x12345678` | One RTP stream |
| `rtpevent.event_id` | DTMF digits dialled |
| `mqtt.msgtype == 3` | MQTT PUBLISH |
| `mqtt.topic contains "sensor"` | MQTT topic names |
| `modbus.func_code == 3` | Read Holding Registers (6 = Write Single) |
| `s7comm.header.rosctr == 1` | S7 job requests |
| `cotp.type == 0x0f` | COTP data, the S7/RDP transport layer |
| `irc.request.command == "PRIVMSG"` | IRC messages, classic C2 |
| `irc.response.command == "001"` | IRC welcome, server identified |
| `telnet.data contains "password"` | Cleartext telnet session |
| `rdp` | RDP after the TLS/CredSSP handshake |
| `tpkt` | TPKT framing under RDP and S7 |

## Filters - usb, wifi, bluetooth

| Display filter | Matches |
|---|---|
| `usb.transfer_type == 0x01` | Interrupt transfers (HID keyboards/mice) |
| `usb.capdata` | Raw captured USB data bytes |
| `usbhid.data` | Parsed HID report bytes |
| `usb.device_address == 3` | One USB device |
| `usb.src == "1.4.1"` | Traffic from one endpoint |
| `wlan.fc.type_subtype == 8` | Beacon frames |
| `wlan.fc.type_subtype == 4` | Probe requests (leaks known SSIDs) |
| `wlan.ssid` | Any frame carrying an SSID |
| `wlan.addr == 00:11:22:33:44:55` | One station |
| `wlan.fc.type == 2` | Data frames only |
| `eapol` | The 4-way handshake (crackable with hashcat) |
| `eapol.keydes.key_info == 0x008a` | Message 1 of the 4-way handshake |
| `wlan.rsn.akms.type == 2` | WPA2-PSK network |
| `radiotap.dbm_antsignal > -50` | Strong signal, transmitter is close |
| `wlan.fc.type_subtype == 12` | Deauthentication frames (attack) |
| `btle` | Bluetooth Low Energy link layer |
| `btatt.value` | BLE GATT attribute values |
| `bthci_evt` | Bluetooth HCI events |

## Extracting fields with -T fields

```sh
# the core recipe: -T fields plus one -e per column, tab-separated by default
tshark -r capture.pcap -Y http.request -T fields -e frame.number -e ip.src -e http.host -e http.request.uri
# comma separator with a header row and quoting, i.e. real CSV
tshark -r capture.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -E header=y -E separator=, -E quote=d
# occurrence=f keeps only the first value when a field repeats in one packet
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -E occurrence=f | sort | uniq -c | sort -rn
# raw hex of a field instead of its formatted value - use for payload carving
tshark -r capture.pcap -Y 'tcp.stream eq 2' -T fields -e data.data | tr -d '\n' | xxd -r -p > stream2.bin
# ICMP payload bytes only, the usual ping-tunnel extraction
tshark -r capture.pcap -Y icmp -T fields -e data.data | tr -d '\n' | xxd -r -p > icmp.bin
# DNS tunnelling: take the first label of every query and decode it
tshark -r capture.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | cut -d. -f1 | tr -d '\n' | base32 -d
# NTLMv2 hash components for hashcat -m 5600
tshark -r capture.pcap -Y ntlmssp -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmserverchallenge -e ntlmssp.auth.ntresponse
# USB HID keystroke bytes, ready to feed a keymap decoder
tshark -r capture.pcap -Y 'usb.transfer_type == 0x01 && usb.capdata' -T fields -e usb.capdata
# -T ek gives newline-delimited JSON suitable for piping into jq or Elastic
tshark -r capture.pcap -Y dns -T ek | jq -r '.layers.dns_dns_qry_name[]?'
```

## Export objects and following streams

```sh
# dump every HTTP-transferred file; protocols: http, smb, tftp, imf, dicom, ftp-data
mkdir -p objs && tshark -r capture.pcap -q --export-objects http,objs
# same for SMB, which is where lateral-movement payloads live
tshark -r capture.pcap -q --export-objects smb,objs_smb
# email messages (IMF) reassembled out of SMTP, attachments included
tshark -r capture.pcap -q --export-objects imf,objs_mail
# identify everything you exported, then carve anything still unknown
file objs/* && binwalk -e objs/*
# follow one TCP stream as ASCII, by stream index
tshark -r capture.pcap -q -z follow,tcp,ascii,3
# follow by endpoint pair instead of index when you do not know the number
tshark -r capture.pcap -q -z follow,tcp,ascii,10.0.0.5:4444,10.0.0.9:51234
# raw form: one hex blob per direction, decode it back to bytes
tshark -r capture.pcap -q -z follow,tcp,raw,3 | tail -n +7 | tr -d '\n' | xxd -r -p > s3.bin
# loop every TCP stream to disk so you can grep them all at once
for i in $(tshark -r capture.pcap -T fields -e tcp.stream | sort -un); do tshark -r capture.pcap -q -z follow,tcp,ascii,$i > stream_$i.txt; done
```

## Decode As, custom ports and TLS decryption

```sh
# force a dissector onto a non-standard port: HTTP on 8888
tshark -r capture.pcap -d tcp.port==8888,http -Y http
# TLS on a non-standard port, needed before any decryption will apply
tshark -r capture.pcap -d tcp.port==8443,tls
# decode a UDP port as DNS (exfil over 5353, 5355, 8053 and friends)
tshark -r capture.pcap -d udp.port==8053,dns -Y dns
# decrypt TLS with an SSLKEYLOGFILE captured from the browser or client
tshark -r capture.pcap -o tls.keylog_file:sslkeys.log -Y http2
# decrypt RSA-key-exchange TLS with the server private key (no PFS suites only)
tshark -r capture.pcap -o 'uat:rsa_keys:"server.key",""' -Y http
# pcapng files can embed the keys in a Decryption Secrets Block - check for one
tshark -r capture.pcapng -Y tls -V | grep -i 'secrets\|decrypted'
# inject a keylog file into a pcapng so the capture is self-contained
editcap --inject-secrets tls,sslkeys.log capture.pcap capture_keys.pcapng
# decrypt WPA2 with the passphrase and SSID (needs the 4-way handshake in the file)
tshark -r wifi.pcap -o 'wlan.enable_decryption:TRUE' -o 'uat:80211_keys:"wpa-pwd","password:SSID"'
```

## Time handling

```sh
# absolute UTC timestamps instead of seconds-since-start
tshark -r capture.pcap -t ad
# delta from the previous displayed packet, the beaconing detector
tshark -r capture.pcap -t d -Y 'ip.dst == 10.0.0.5'
# filter by absolute time, quoting the whole comparison
tshark -r capture.pcap -Y 'frame.time >= "2024-05-01 10:00:00" && frame.time < "2024-05-01 10:05:00"'
# filter by offset from the start of the capture
tshark -r capture.pcap -Y 'frame.time_relative > 60 && frame.time_relative < 120'
# shift every timestamp by an offset to align two captures from skewed clocks
editcap -t -3600 capture.pcap shifted.pcap
# inter-arrival histogram for one destination: constant gaps mean automated beacons
tshark -r capture.pcap -Y 'ip.dst == 10.0.0.5 && tcp.flags.syn == 1' -T fields -e frame.time_delta_displayed | sort -n | uniq -c
```

## tcpdump BPF equivalents

| tshark display filter | tcpdump capture filter (BPF) |
|---|---|
| `ip.addr == 10.0.0.5` | `host 10.0.0.5` |
| `ip.src == 10.0.0.5` | `src host 10.0.0.5` |
| `ip.dst == 10.0.0.0/24` | `dst net 10.0.0.0/24` |
| `tcp.port == 443` | `tcp port 443` |
| `tcp.dstport == 443` | `tcp dst port 443` |
| `udp.port in {53 5353}` | `udp port 53 or udp port 5353` |
| `tcp.port >= 1024 && tcp.port <= 2048` | `tcp portrange 1024-2048` |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | `tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0` |
| `tcp.flags.reset == 1` | `tcp[tcpflags] & tcp-rst != 0` |
| `icmp.type == 8` | `icmp[icmptype] = icmp-echo` |
| `arp` | `arp` |
| `eth.addr == 00:11:22:33:44:55` | `ether host 00:11:22:33:44:55` |
| `vlan.id == 20` | `vlan 20` |
| `ip.len > 500` | `ip[2:2] > 500` |
| `frame.len < 64` | `less 64` |
| `!(ip.addr == 10.0.0.1)` | `not host 10.0.0.1` |
| `tcp.len > 0` | `tcp and (ip[2:2] - ((ip[0]&0xf)<<2) - ((tcp[12]&0xf0)>>2)) != 0` |

```sh
# capture filters go on -f in tshark and are the only thing that works while capturing live
tshark -i eth0 -f 'tcp port 4444 and not host 10.0.0.1' -w live.pcap
# tcpdump reading a file with a BPF filter, -n skips DNS resolution, -A prints ASCII
tcpdump -nnr capture.pcap -A 'tcp port 80'
```

## tcpflow, ngrep, zeek and NetworkMiner

```sh
# tcpflow reassembles every TCP session into one file per direction in the cwd
tcpflow -r capture.pcap -o flows/
# tcpflow with all scanners on: carves HTTP bodies, extracts objects, writes a report
tcpflow -r capture.pcap -o flows/ -e http -e netviz -a
# grep across reassembled flows, which beats grepping raw packets
grep -ra 'flag{' flows/
# ngrep: regex over packet payloads with a BPF filter, -q quiet, -I reads a file
ngrep -q -I capture.pcap -i 'password|passwd|pwd' 'tcp'
# zeek generates conn.log, dns.log, http.log, files.log, ssl.log, notice.log
zeek -r capture.pcap
# zeek with the file-extraction script: every transferred file lands in extract_files/
zeek -r capture.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
# zeek-cut turns the TSV logs into just the columns you care about
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes
# NetworkMiner CLI on Linux via mono: auto-extracts files, creds, images, DNS
mono /opt/NetworkMiner/NetworkMinerCLI.exe -r capture.pcap -w ./nm_out
# last resort when nothing dissects: carve file signatures straight out of the pcap
foremost -i capture.pcap -o carved && binwalk -e capture.pcap
```

## Wireshark GUI equivalents

| GUI action | tshark equivalent |
|---|---|
| Statistics > Protocol Hierarchy | `-q -z io,phs` |
| Statistics > Conversations | `-q -z conv,tcp` |
| Statistics > Endpoints | `-q -z endpoints,ip` |
| Statistics > IO Graph | `-q -z io,stat,1` |
| Statistics > Flow Graph | `-q -z flow,tcp,network` |
| Analyze > Expert Information | `-q -z expert` |
| File > Export Objects > HTTP | `-q --export-objects http,dir` |
| Follow > TCP Stream | `-q -z follow,tcp,ascii,N` |
| Analyze > Decode As | `-d tcp.port==8888,http` |
| Edit > Preferences > Protocols > TLS > keylog | `-o tls.keylog_file:keys.log` |
| Edit > Find Packet > String > Packet bytes | `-Y 'frame contains "str"'` |
| View > Time Display Format > UTC | `-t ad` |
| File > Export Packet Dissections > CSV | `-T fields -E header=y -E separator=,` |
| File > Export Specified Packets | `-Y 'filter' -w out.pcap` |
| Statistics > Capture File Properties | `capinfos -A file.pcap` |
| File > Merge | `mergecap -w out.pcap a.pcap b.pcap` |
| Telephony > VoIP Calls | `-q -z sip,stat` |
| Apply as Filter > Selected | copy the field name into `-Y` |

## References

- Wireshark display filter reference (`wireshark-filter(4)`, `tshark -G fields`)
- `tshark(1)`, `editcap(1)`, `mergecap(1)`, `capinfos(1)` man pages
- `pcap-filter(7)` for the BPF capture filter grammar
- Zeek log reference and `zeek-cut`; tcpflow and ngrep man pages
