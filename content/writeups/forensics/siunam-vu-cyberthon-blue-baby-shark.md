---
title: "Blue-Baby-Shark - VU-Cyberthon 2023"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "blue-baby-shark", "network", "forensic"]
summary: "In this challenge, we can download a file:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark/README.md"
ctf:
  name: "VU-Cyberthon"
  year: 2023
  challenge: "Blue-Baby-Shark"
---

## Source

- **CTF:** VU-Cyberthon 2023
- **Challenge:** Blue-Baby-Shark
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark/README.md>

---
# Blue Baby Shark

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225155515.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark)-[2023.02.25|15:54:42(HKT)]
└> file Blue\ Baby\ Shark.pcapng 
Blue Baby Shark.pcapng: pcapng capture file - version 1.0
```

It's a packet capture file!

**Let's open it in WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark)-[2023.02.25|15:55:32(HKT)]
└> wireshark Blue\ Baby\ Shark.pcapng
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160047.png)

**Let's look at the "Protocol Hierarchy" in "Statistics" tab:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160126.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160143.png)

In here, we see there are 3 protocols: **Dropbox LAN sync Discovery**, TCP, ICMP.

The Dropbox protocol looks very interesting, as sometimes bad actors will use Dropbox to host their C2 (Command and Control) infrastructure:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160321.png)

Hmm... No idea what we can do with that at the moment.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160353.png)

In the bottom of the packet capture, I saw that very sussy data.

**Let's follow it's TCP stream:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160434.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160442.png)

Oh! Looks like we found some commands traffic's data!

**When you scroll down, we can see the flag:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160546.png)

- **Flag: `VU{b4by_5h4rk_fly_4w4y}`**

# Conclusion

What we've learned:

1. Analyzing How A Bad Actor Infiltrate A System Via Inspecting Packets In WireShark
