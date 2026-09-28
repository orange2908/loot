---
title: "Chronos - boroCTF 2026"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["pcap", "forensics", "tshark", "morse", "subprocess", "network", "boroctf", "boroctf-2026", "2026", "ctf-writeup"]
summary: "CTF BoroCTF Forensics PCAP"
source:
  name: "CTFtime writeup #40868"
  url: "https://ctftime.org/writeup/40868"
original_source: "https://vignesh.zip/posts/2026/boroctf/chronos.html"
ctf:
  name: "boroCTF 2026"
  year: 2026
  challenge: "Chronos"
---

## Metadata

- **CTF:** boroCTF 2026
- **Task:** Chronos
- **Author team:** 0ddC0der
- **CTFtime tags:** pcap, forensics
- **CTFtime:** <https://ctftime.org/writeup/40868>
- **Original writeup:** <https://vignesh.zip/posts/2026/boroctf/chronos.html>

---
## Forensics — Chronos

CTF BoroCTF Forensics PCAP

Jun 2026 · 5 min read

### Introduction

Going by the title of the challenge, I suspect this will be related to _data exfil_ of some sort. 

```
    Description
    -----------
    Would you rather posess the powers of Chronos, 
    the God of Time or posess the powers of a bilingual?
```

**Handout:** [chronos.pcap](https://vignesh.zip/assets/handouts/2026/boroctf/chronos.pcap)

### Recon

When I first opened `chronos.pcap`, there was only SYN packets without much additional info. The overall shape was odd — three hundred packets spread across two and a half minutes. Unusually slow for a network activity. So I started looking for data in the packets. 

```
    tshark -r chronos.pcap -q -z io,stat,0
```

```
    Duration: 155.8 secs
    Frames:   312
    Bytes:    12480
```

### What's inside the packets?

I checked the protocol details to make sure I wasn't missing plaintext in the payload:

  * IPv4 TCP, source `10.10.10.5:4444` → `192.168.1.20:80`
  * TCP flags: **SYN only** , no payload data
  * TCP window size: **8192** on every packet (constant — not the flag channel)


312 identical-looking SYN packets with nothing to read _inside_. Dead end for data exfiltration.

Given the unusual time taken for the packets. I corelated with the challenge title and checked the per-packet timing:

```
    tshark -r chronos.pcap -T fields \
      -e frame.number -e frame.time_relative -e frame.time_delta -e frame.len \
      | head -20
```

```
    1    0.000000000                  40
    2    0.750000000    0.750000000    40
    3    1.500000000    0.750000000    40
    4    1.750000000    0.250000000    40
    5    2.000000000    0.250000000    40
    ...
```

Few information from this:

  1. **Every packet is exactly 40 bytes.** Same size, all the way through.
  2. **Only two gap values** between packets: `0.250` seconds and `0.750` seconds.
  3. **The ratio is 1:3** — short gap, long gap. Dot and dash shape, maybe _Morse?_


### Building the bitstream

I tried greedy Morse decode first — that produced gibberish like `:XYQZXYQ4;=32)=...` I considered the short interval packets as dots and longer interval packets as dashes; no proper decoding so not Morse. If not morse, then it has to be _binary_

Unique time deltas across the capture:

  * `0.250 s` — 155 times → bit `0`
  * `0.750 s` — 156 times → bit `1`


311 measurements total (packet 1 has no previous packet to compare against).

### The alignment problem

The flag format `boroCTF{...}` — so 312/8 = 39 ASCII characters. But inter-packet deltas only give **311 bits** (packets 2 through 312). 

Decoding 311 bits at various offsets mostly gave garbage. One offset was almost readable but missing the leading `b`: `oroCTF{c0mbobulat3_sp@gh3tti_nep0t1$m}`. 

**Prepending a single`0` bit** for packet 1. That gives exactly 312 bits and decodes cleanly. 

### Solve script

```
    import subprocess
    out = subprocess.check_output(
      ["tshark", "-r", "chronos.pcap", "-T", "fields", "-e", "frame.time_delta"],
      text=True,
    )
    deltas = [float(x) for x in out.splitlines() if x.strip()]
    print(deltas)
    print("count:", len(deltas)) # 311
    
    bits = "0" + "".join(
      "0" if abs(d - 0.25) < 0.01 else "1"
      for d in deltas
    )
    
    flag = "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))
    print(flag)
    #boroCTF{c0mbobulat3_sp@gh3tti_nep0t1$m}
```

```
    FLAG: boroCTF{c0mbobulat3_sp@gh3tti_nep0t1$m}
```
