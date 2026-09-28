---
title: "Mahashamshan - Kashi CTF 2026"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "xor", "pcap", "wireshark", "mahashamshan", "network", "kashi-ctf", "kashi-ctf-2026", "2026", "ctf-writeup"]
summary: "During the initial inspection of the pcap in Wireshark, most traffic appeared to be ordinary background noise: TCP SYN/ACK packets, ARP requests, and ICMP."
source:
  name: "CTFtime writeup #40691"
  url: "https://ctftime.org/writeup/40691"
original_source: "https://github.com/pnimtsovych/WriteUp/tree/main/Mahashamshan%20(Kashi%20CTF%202026)"
ctf:
  name: "Kashi CTF 2026"
  year: 2026
  challenge: "Mahashamshan"
---

## Metadata

- **CTF:** Kashi CTF 2026
- **Task:** Mahashamshan
- **Author team:** LeetSh4d0ws
- **CTFtime:** <https://ctftime.org/writeup/40691>
- **Original writeup:** <https://github.com/pnimtsovych/WriteUp/tree/main/Mahashamshan%20(Kashi%20CTF%202026)>

---
# Mahashamshan

## Category: Forensics

#### A packet capture was pulled from a compromised node inside a covert communications network. The operator who extracted it left only one note before going dark:

#### "The river does not reveal itself. It only flows."

#### Your tools will lie to you. Your instincts will betray you. There are many ragebaits. There are fake helpers too becareful. It has always been in the packets. "Not all fields are what they seem. The fragment offset field hides more than offset."

![image](<https://github.com/user-attachments/assets/1d13654d-7e0c-4201-9bfb-d80f94324d49>)

During the initial inspection of the pcap in Wireshark, most traffic appeared to be ordinary background noise: TCP SYN/ACK packets, ARP requests, and ICMP. However, several packets stood out as Fragmented IP protocol (proto=TCP 6, off=40, ID...). Since the challenge explicitly hinted that “the fragment offset field hides more than offset”, these packets immediately became the main focus of the analysis.

![image](<https://github.com/user-attachments/assets/bb9f1395-6c47-4d47-ab7d-035bfafda498>)

A detailed look at one of the suspicious Fragmented IP protocol packets revealed an HTTP-like payload (POST /api/v1/sync HTTP/1.1), but it turned out to be a distraction. This confirmed that the hidden data should be looked for in the header fields, not in the payload.

![image](<https://github.com/user-attachments/assets/1f5a6dcc-b508-4553-8cee-126b4cb6b6fc>)

After analyzing one of the packets marked as Fragmented IP protocol, it was found that its Data field contained an HTTP-like string POST /api/v1/sync HTTP/1.1. Further inspection showed that this same fragment is repeated in all suspicious packets of the same type. Since filtering by fragment offset fields in Wireshark did not provide a stable selection, the filter `frame contains "POST /api/v1/sync"` was used for practical isolation of this group. This allowed collecting all relevant packets, which were then analyzed at the header field level.

After isolating 41 matching packets, I compared them. The HTTP-like payload (POST /api/v1/sync HTTP/1.1) was the same in each of them, so it could not directly contain unique flag characters and most likely acted as a decoy. Instead, the IP Identification values and the first bytes of the fragment payload before the POST line changed, which indicated a real covert channel.

Further analysis showed that the bytes `payload[4:8]` formed a sequence of values of the form `123456 * n`, so they could be used as a character ordering key. At the same time, the low-order byte of the IP Identification field, after XORing with `0x21`, produced a readable ASCII character. Thus, each of the 41 packets contained exactly one flag character, and its position was determined separately:

```python  
order = int.from_bytes(payload[4:8], "big") // 123456  
char = chr((ip_id & 0xff) ^ 0x21)  
```

To automate this process, I used a Python script called `[solve.py](http://solve.py)`. The script went through all the packets in pcap, selected only those that contained the `POST /api/v1/sync` marker, extracted the order value from `payload[4:8]`, took the low-order byte of the IP Identification, decoded the character via XOR with `0x21`, then sorted all the characters by order and combined them into a final string.

### Automation script

```python  
import struct

path = "mahashamshan_2.pcap"  
rows = []

with open(path, "rb") as f:  
f.read(24) # pcap global header

while True:  
hdr = f.read(16)  
if len(hdr) < 16:  
break

ts_sec, ts_usec, incl_len, orig_len = struct.unpack("
