---
title: "USBNet - Nullcon Goa HackIM 2025 CTF"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "qr-code", "cyberchef", "usbnet", "network", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Analyzed PCAP file in Wireshark Found PNG file signature in one of the packets Extracted hex data and processed through CyberChef revealing a QR code Scanned QR code to get the flag"
source:
  name: "CTFtime writeup #39979"
  url: "https://ctftime.org/writeup/39979"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/rJT7s18Ykl"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "USBNet"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** USBNet
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39979>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/rJT7s18Ykl>

---
Analyzed PCAP file in Wireshark Found PNG file signature in one of the packets Extracted hex data and processed through CyberChef revealing a QR code Scanned QR code to get the flag

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
