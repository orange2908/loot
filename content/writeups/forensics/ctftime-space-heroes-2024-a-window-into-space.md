---
title: "A Window into Space - Space Heroes 2024"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "python", "pcapng", "scapy", "wireshark", "window", "space", "network", "space-heroes", "space-heroes-2024", "2024", "ctf-writeup"]
summary: "We are given with a pcapng file: space.pcapng"
source:
  name: "CTFtime writeup #39052"
  url: "https://ctftime.org/writeup/39052"
original_source: "https://github.com/pspspsps-ctf/writeups/tree/main/2024/Space%20Heroes%202024/Forensics/A%20Window%20into%20Space"
ctf:
  name: "Space Heroes 2024"
  year: 2024
  challenge: "A Window into Space"
---

## Metadata

- **CTF:** Space Heroes 2024
- **Task:** A Window into Space
- **Author team:** pspspsps
- **CTFtime tags:** python, pcapng, scapy, wireshark
- **CTFtime:** <https://ctftime.org/writeup/39052>
- **Original writeup:** <https://github.com/pspspsps-ctf/writeups/tree/main/2024/Space%20Heroes%202024/Forensics/A%20Window%20into%20Space>

---
# A Window into Space

> I think aliens are testing us again and they they are poking fun at our internet protocols by using them in close proximity to earth. We were able to intercept something but I cant figure out what it is. Take a crack at it for me.  
>   
> Author: Josh

Solution:

We are given with a pcapng file: `space.pcapng`

Let's check the protocol hierarchy first

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Forensics/A%20Window%20into%20Space/1.png>)

Hmm, nothing noticeable immediately.

Decided to check each packet instead and noticed that it forms `shctf{` in the window.

![gif](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Forensics/A%20Window%20into%20Space/wireshark.gif>)

So we can filter by `ip.dst == 172.20.2.136 && tcp.dstport == 8008`

Decided to use scapy to make things easier.

```python  
from scapy.all import *

flag = []

packets = rdpcap("space.pcapng")

for pkt in packets:  
if TCP in pkt and pkt[TCP].dport == 8008 and pkt[IP].dst == '172.20.2.136':  
# Get the TCP window size  
window_size = pkt[TCP].window  
character = chr(window_size)  
flag.append(character)  
print(f'Window size: {window_size} -> ASCII: {character}')

print(''.join(flag))  
```

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Forensics/A%20Window%20into%20Space/2.png>)

Boom!

Flag: `shctf{1_sh0uld_try_h1d1ng_1n_th3_ch3cksum_n3xt_t1me_0817}`
