---
title: "Tunnel? - KubSTU CTF"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "wireshark", "side-channel", "tunnel", "network", "kubstu-ctf", "ctf-writeup"]
summary: "Open the dump in the WireShark."
source:
  name: "CTFtime writeup #40766"
  url: "https://ctftime.org/writeup/40766"
ctf:
  name: "KubSTU CTF"
  challenge: "Tunnel?"
---

## Metadata

- **CTF:** KubSTU CTF
- **Task:** Tunnel?
- **Author team:** μAGMA
- **CTFtime:** <https://ctftime.org/writeup/40766>

---
Side channel leakage.

Open the dump in the WireShark. See a lot of noise packets. Analyse the packet size distribution and see that there two groups of sizes: more than 500 bytes and less than 100 bytes.

Filter out the packets of size less than 100 bytes. Most of them are DNS requests of the same format. Among them see a rare requests that differ from others - requests to resolve a host of this form: [v00.4b75.exfiltrate.kubstu-ctf.ru](http://v00.4b75.exfiltrate.kubstu-ctf.ru).

Collect all such packets from v00 to v20 - 21 packtes. The 5-th level domain is the sequence number, the 4-th level domain is payload. Concatenate all the payload and decode it as hex to the ASCII to get the flag.
