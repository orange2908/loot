---
title: "Tool - Wireshark / tshark"
category: forensics
subcategory: network-forensics
type: tool
tags: [wireshark, tshark, pcap, pcapng, packet-capture, follow-stream, export-objects, display-filter, network-forensics, tls-decryption, usb, dns-exfil, capinfos, editcap, mergecap]
summary: "Read, filter and extract from packet captures; tshark is the scriptable CLI half that belongs in every pcap workflow."
related: [forensics-triage, scapy, nmap, binwalk]
---

## What it is

Wireshark is the packet analyser; `tshark` is its command-line interface. For CTF, `tshark` does the work (filtering, statistics, bulk extraction) and the GUI does the parts that need eyes (Follow Stream, protocol tree inspection).

## Install

```sh
# macOS
brew install --cask wireshark        # GUI + CLI
brew install wireshark               # CLI only
# Debian/Ubuntu/Kali
sudo apt install wireshark tshark
sudo dpkg-reconfigure wireshark-common   # allow non-root capture
sudo usermod -aG wireshark "$USER"
# verify
tshark -v | head -1
```

## The invocations that matter

```sh
PCAP=capture.pcap

# 1. protocol hierarchy - the single most informative command on any pcap
tshark -r "$PCAP" -q -z io,phs

# 2. conversations, sorted by volume
tshark -r "$PCAP" -q -z conv,tcp
tshark -r "$PCAP" -q -z conv,udp
tshark -r "$PCAP" -q -z endpoints,ip

# 3. extract fields with a display filter (the workhorse pattern)
tshark -r "$PCAP" -Y 'http.request' -T fields -e frame.number -e http.host -e http.request.uri
tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u

# 4. export every transferred file automatically
tshark -r "$PCAP" --export-objects http,out_http/
tshark -r "$PCAP" --export-objects smb,out_smb/
tshark -r "$PCAP" --export-objects tftp,out_tftp/
tshark -r "$PCAP" --export-objects imf,out_mail/
tshark -r "$PCAP" --export-objects dicom,out_dicom/

# 5. follow a stream from the CLI
tshark -r "$PCAP" -q -z follow,tcp,ascii,0      # stream index 0
tshark -r "$PCAP" -q -z follow,tcp,raw,3 | tail -n +7 | tr -d '\n' | xxd -r -p > stream3.bin

# 6. credentials and interesting plaintext
tshark -r "$PCAP" -Y 'http.authorization || ftp.request.command == "PASS" || telnet' -T fields -e _ws.col.Info

# 7. decrypt TLS with a keylog file
tshark -r "$PCAP" -o tls.keylog_file:sslkeylog.txt -Y http

# 8. capture statistics and time range
capinfos "$PCAP"
tshark -r "$PCAP" -T fields -e frame.time_epoch -e ip.src -e ip.dst | head

# 9. split, merge, convert
editcap -c 10000 big.pcap chunk.pcap        # split into 10k-packet files
editcap -A '2024-01-01 00:00:00' -B '2024-01-02 00:00:00' in.pcap out.pcap
mergecap -w all.pcap a.pcap b.pcap
editcap -F pcap in.pcapng out.pcap          # pcapng -> classic pcap for old tools

# 10. raw payload bytes of matching packets
tshark -r "$PCAP" -Y 'tcp.port==1337 && tcp.len>0' -T fields -e data.data | tr -d '\n' | xxd -r -p > payload.bin
```

Display filters you will reuse:

| Filter | Matches |
|---|---|
| `http.request` / `http.response` | HTTP |
| `http.request.method == "POST"` | POSTs (form data, uploads) |
| `http contains "flag"` | payload substring |
| `frame contains "flag{"` | any packet containing the bytes |
| `dns.qry.name contains "."` | DNS queries |
| `icmp && data.len > 16` | ICMP tunnelling |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | connection attempts (port scan) |
| `tcp.stream == 5` | one conversation |
| `ip.addr == 10.0.0.5 && tcp.port == 4444` | a specific channel |
| `tls.handshake.type == 1` | TLS Client Hello (SNI is here) |
| `usb.transfer_type == 0x01` | USB interrupt transfers (keyboards/mice) |
| `smb2.cmd == 5` | SMB2 create (file access) |
| `ftp-data` | FTP file contents |
| `eapol` | WPA handshake |
| `!(arp \|\| stp \|\| cdp)` | hide the noise |
| `frame.len > 1000` | large packets (data transfer) |

Note: **capture filters** (`-f`, BPF syntax) and **display filters** (`-Y`, Wireshark syntax) are different languages. In CTF you almost always want `-Y`.

GUI shortcuts that matter: right-click -> Follow -> TCP/UDP/HTTP Stream; File -> Export Objects; Statistics -> Protocol Hierarchy / Conversations; Edit -> Find Packet (set to "Packet bytes" + "String"); View -> Time Display Format -> Seconds Since Beginning.

## Gotchas

- `-Y` (display filter) is applied after full dissection; `-f` (capture filter) is BPF and applies while capturing. Mixing them up produces empty output.
- `tshark` needs `-r` for a file. Without it, it tries to capture live and may need root.
- `--export-objects` only works for protocols Wireshark can reassemble, and only if the stream is complete. For anything else, carve with `foremost -i capture.pcap`.
- TLS cannot be decrypted without either the session keys (`SSLKEYLOGFILE`) or, for old RSA key exchange only, the server's private key. If the handshake uses ECDHE, the private key is useless.
- Follow Stream in the GUI with "Show data as: Raw" then Save As is the reliable way to extract binary payloads; the ASCII view mangles them.
- Reassembly is off for some protocols by default: `-o tcp.desegment_tcp_streams:TRUE`.
- Large pcaps: `tshark` loads incrementally but `-z` statistics still need a full pass. Split with `editcap` first.
- Field names change between Wireshark versions. `tshark -G fields | grep <name>` lists what your build supports.
- On macOS the CLI tools install under `/Applications/Wireshark.app/Contents/MacOS/` when you install the cask; add it to `PATH` or use `brew install wireshark` for the CLI.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Custom protocol dissection | `scapy` (`ctfbrain search scapy`) |
| Bulk file carving from a pcap | `foremost -i f.pcap`, `binwalk -e`, `networkminer` |
| Automated credential extraction | `pcredz`, `networkminer`, `chaosreader` |
| HTTP-focused analysis | `mitmproxy` (`mitmproxy -r f.pcap` reads flows), `httpry` |
| Very large captures | `tcpdump -r f.pcap -w filtered.pcap '<bpf>'` first, then tshark |
| Live capture | `tcpdump -i any -w out.pcap` |
| Zeek-style summarisation | `zeek -r f.pcap` produces conn.log, http.log, dns.log, files.log |
