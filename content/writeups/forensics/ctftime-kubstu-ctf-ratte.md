---
title: "Ratte - KubSTU CTF"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "xor", "pcap", "wireshark", "ratte", "network", "kubstu-ctf", "ctf-writeup"]
summary: "Open the pcap dump in WireShark."
source:
  name: "CTFtime writeup #40764"
  url: "https://ctftime.org/writeup/40764"
ctf:
  name: "KubSTU CTF"
  challenge: "Ratte"
---

## Metadata

- **CTF:** KubSTU CTF
- **Task:** Ratte
- **Author team:** μAGMA
- **CTFtime:** <https://ctftime.org/writeup/40764>

---
Open the pcap dump in WireShark. Use dialog analysis to see that mostly all diaglogs are unique and contain only one packet.

The only exception is communication between two hosts on TCP port 1337. You see 21 packets. The first one contains payload `0xDE 0xAD 0xBE 0xEF 0x42`. All other packets contain `0xCC 0x?? 0x02 0x?? 0x??` payload except for the last one which is `0xCC 0x?? 0x01 0x??`.

Make an assumption that the first byte `0xCC` is some kind of payload indicator. The third byte contains the length of data. Second byte is some noise. Collect and concatenate the data from all the packets and XOR it with `0x42` (the fifth byte of first packet after `0xDE 0xAD 0xBE 0xEF`) - you've got the flag.
