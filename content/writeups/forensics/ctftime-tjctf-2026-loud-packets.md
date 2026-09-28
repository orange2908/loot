---
title: "loud-packets - TJCTF 2026"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "spectrogram", "loud-packets", "network", "tjctf", "tjctf-2026", "2026", "ctf-writeup"]
summary: "We're given a pcap capture file (chall.pcap) containing 509 UDP packets."
source:
  name: "CTFtime writeup #40786"
  url: "https://ctftime.org/writeup/40786"
original_source: "https://blog.rawpayload.com/blog/tjctf-2026-loud-packets-writeup"
ctf:
  name: "TJCTF 2026"
  year: 2026
  challenge: "loud-packets"
---

## Metadata

- **CTF:** TJCTF 2026
- **Task:** loud-packets
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40786>
- **Original writeup:** <https://blog.rawpayload.com/blog/tjctf-2026-loud-packets-writeup>

---
Overview  
We're given a pcap capture file (chall.pcap) containing 509 UDP packets. The flag is hidden as pixel-art text rendered in the audio spectrogram of a custom streaming protocol.

Step 1 — Identifying the Protocol  
The pcap contains two types of traffic:

459 "main" packets from 192.168.1.100:50000 → 192.168.1.200:62000, each carrying a payload with a 4-byte ASCII magic BTAV, a 4-byte big-endian sequence number (0–458), and 600 bytes of data (except the final packet which has 428 bytes).  
50 "decoy" packets from random 10.0.0.x addresses with random-looking encrypted payloads — these are red herrings.  
Pkt 0: 42 54 41 56 00 00 00 ae 00 00 00 00 ... B T A V [seq=174] [600 bytes audio data]

Step 2 — Reassembling the Audio

Step 3 — Reading the Spectrogram
