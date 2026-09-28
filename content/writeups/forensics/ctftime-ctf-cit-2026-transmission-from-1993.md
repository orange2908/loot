---
title: "Transmission from 1993 - CTF@CIT 2026"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "tshark", "transmission", "network", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The PCAP is a SIP call that starts as RTP audio and later switches to a T.38 fax session."
source:
  name: "CTFtime writeup #40734"
  url: "https://ctftime.org/writeup/40734"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Transmission from 1993"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Transmission from 1993
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40734>

---
# Transmission from 1993 — Writeup

\- Category: Forensics  
\- Value: 968  
\- Author: hypnos

## Challenge

> REEEEEE–KRRR–SKREEEEEE–BEEP BEEP BEEP  
>  
> **SHA1:** `6d69c28f3a8d3ba2a07ca95bdc7646f90dfb540e`

## Recon

The PCAP is a SIP call that starts as RTP audio and later switches to a T.38 fax session.  
The obvious trap is assuming the image payload is ordinary Group 3 fax data because Wireshark exposes it as `t30.t4.data`.  
That path only renders garbage scanlines.

The useful clue is in the T.30 control exchange.  
Frame `865` is the receiver DIS and frame `924` is the sender DCS.  
The DCS disables normal 2D/T.6 fax coding but keeps `Single-progression sequential coding (ITU-T T.85)` enabled.

That means the image is T.85/JBIG1, not plain CCITT Group 3.

## Solve

First extract the ECM payload blocks from the T.38 session:

```bash  
tshark -r files/call-69e26052e9f5b0c1da0ee369.pcap \  
-Y 't30.t4.data' \  
-T fields \  
-e t30.t4.frame_num \  
-e t30.t4.data  
```

This yields eight ECM blocks, numbered `0` through `7`, each `256` bytes long.  
Concatenate them in order to recover the fax image payload.

The next trick is bit order.  
Fax data is transmitted least-significant-bit first, so the payload must be bit-reversed byte-by-byte before feeding it to a T.85 decoder.  
After reversing each byte, `jbgtopbm85` starts decoding the image correctly.

The full `2048`-byte stream still has trailing garbage or padding, but the decoder reveals how much valid JBIG data it consumed:

```text  
1996 = 0x07cc BIE bytes and 2156 pixel rows processed  
```

Trimming the bit-reversed stream to `1996` bytes and decoding again produces a clean `1728 x 2156` fax page.  
The page reads:

```text  
Wooooo! Good job!  
CIT{fL3x_Y0ur_F4xiNG}  
```

## Flag

```text  
CIT{fL3x_Y0ur_F4xiNG}  
```

## Files

\- [scripts/[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py))  
\- [solution/flag.txt](solution/flag.txt)  
\- [other/t85/decode.log](other/t85/decode.log)  
\- [other/t85/page.png](other/t85/page.png)  
\- [other/t85/page_crop.png](other/t85/page_crop.png)  
\- [other/t85/flag_crop.png](other/t85/flag_crop.png)
