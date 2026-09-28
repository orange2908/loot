---
title: "Tshark (Forensics)"
category: "forensics"
subcategory: "network"
type: "technique"
tags: ["my-notes", "personal", "pcap", "tshark", "forensics"]
summary: "Personal note: Tshark (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Tshark.md"
---

## Export http objects and putting them inside a folder called payload

```bash
tshark -r 2019-11-12_21:00:30-EXT07.pcap --export-objects http,payloads/
```
### Export ICMP packets data
```bash
tshark -r error_reporting.pcap -Y "ip.src == 192.168.10.113" -T fields -e data
```
### export encrypted TCP packets
```bash
tshark -tud -n -r capture.pcap -E separator=/t -T fields -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e data tcp and data.len != 0 > dump.txt
```

---

*From your own notes: `Forensics/Tshark.md`*
