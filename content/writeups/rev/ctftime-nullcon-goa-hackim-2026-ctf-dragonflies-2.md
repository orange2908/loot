---
title: "DragoNflieS - Nullcon Goa HackIM 2026 CTF"
category: "rev"
subcategory: "network"
type: "writeup"
tags: ["rev", "scapy", "dragonflies", "network", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge involves a DNS server at 52.59.124.14 listening on UDP ports 5053 and 853."
source:
  name: "CTFtime writeup #40595"
  url: "https://ctftime.org/writeup/40595"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "DragoNflieS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** DragoNflieS
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40595>

---
**Challenge Description**:  
The challenge involves a DNS server at `52.59.124.14` listening on UDP ports 5053 and 853. The goal is to solve the challenge by identifying the correct protocol/configuration.

**Analysis**:  
1\. **Port Scanning**:  
\- UDP 5053: Open. Responds to `dig @52.59.124.14 -p 5053 TXT [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)` with "NOPE".  
\- UDP 853: Open. This is the standard port for DNS-over-QUIC (DoQ) or DNS-over-DTLS.  
\- TCP 443/5053/853: Closed/Filtered.

2\. **DNS Probing**:  
\- Queries for `[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)` return "NOPE" or "FAKEFLAG" `ENO{Zzzzt_Zzzzt_FAKEFLAG_Zzzzt}` depending on the query type/subnet.  
\- EDNS Client Subnet (ECS) probing with `127.0.0.1` and `10.0.0.0/8` returned the same "FAKEFLAG".  
\- EDNS Padding (Option 12) was found to be echoed by the server, but changing padding length (0-4096 bytes) did not reveal the real flag.

3\. **Protocol Investigation**:  
\- **DoQ (DNS-over-QUIC)**: Attempts to handshake on UDP 853 using `aioquic` with ALPNs `doq`, `h3`, `dragonflies`, and `Zzzzt` timed out.  
\- **DTLS**: Handshakes on UDP 853 timed out.  
\- **SAE (Dragonfly Key Exchange)**: Given the challenge name "Dragonflies" and the "Zzzzt" hint (buzzing sound), we hypothesized the use of the SAE protocol (WPA3) over UDP. Probe attempts using `scapy` with passwords `Zzzzt` and `ENO` timed out.

4\. **ECS Subnet Guessing**:  
\- The user provided a hint: "need to guess subnet" with `dig +subnet=...`.  
\- Brute-forcing common private subnets (`192.168.x.x`, `10.0.x.x`) failed.  
\- Recalling the **Zoney** challenge (port 5054), the domain `[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)` resolved to the private IP `10.13.37.1`.  
\- Hypothesis: The Dragonflies server (port 5053) filters responses based on the client's subnet, allowing access only from the "internal" network found in Zoney.  
\- Testing `dig +subnet=10.13.37.1/32 @52.59.124.14 -p 5053 [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net) TXT` succeeded.

**Conclusion**:  
The challenge required using the EDNS Client Subnet (ECS) option to impersonate a client from the internal network (`10.13.37.x`), which was discovered in the previous "Zoney" challenge. The "Dragonflies" name and "Zzzzt" hints were likely thematic distractions or references to the "Whirr" sound in the final flag.

**Flag**: `ENO{Whirr_do_not_send_private_data_for_wrong_IP_Whirr}`
