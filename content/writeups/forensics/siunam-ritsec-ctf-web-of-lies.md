---
title: "Web of-Lies - RITSEC-CTF 2023"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "web", "of-lies", "network"]
summary: "forensics writeup for \"Web of-Lies\" from RITSEC-CTF - techniques: pcap, wireshark, web, of-lies, network."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies/README.md"
ctf:
  name: "RITSEC-CTF"
  year: 2023
  challenge: "Web of-Lies"
---

## Source

- **CTF:** RITSEC-CTF 2023
- **Challenge:** Web of-Lies
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies/README.md>

---
# Web of Lies

- 98 Points / 79 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

We found more weird traffic. We're concerned he's connected to a web of underground criminals.

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402133408.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies)-[2023.04.02|13:34:41(HKT)]
└> file weboflies.pcapng 
weboflies.pcapng: pcapng capture file - version 1.0
```

It's a packet capture file!

**We can open it via WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies)-[2023.04.02|13:34:42(HKT)]
└> wireshark weboflies.pcapng
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402133535.png)

In "Statistcs" -> "Protocol Hierarchy", we can view which protocol is being captured:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402133548.png)

As you can see, it has some HTTP packets.

**Let's "Follow HTTP Stream"!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134151.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134200.png)

Hmm... "Flag's not here".

In WireShark, we can export all the HTTP object via:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134422.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134448.png)

**Then `cat` all of them:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies/http)-[2023.04.02|13:42:59(HKT)]
└> cat *              
Flag Not Found
[...]
Flag's not here
[...]
```

Umm... All of them are not the real flag...

After fumbling around, I still don't know what can I do with those packets...
