---
title: "Basic Forensic Methodology (HackTricks)"
category: "forensics"
subcategory: "basic-forensic-methodology"
type: "reference"
tags: ["hacktricks", "forensics", "memory-forensics", "pcap", "basic", "forensic", "methodology", "basic-forensic-methodology"]
summary: "../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md"
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/generic-methodologies-and-resources/basic-forensic-methodology/README.md"
license: "CC BY-NC 4.0"
---

# Basic Forensic Methodology


## Creating and Mounting an Image


../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md

## Malware Analysis

This **isn't necessary the first step to perform once you have the image**. But you can use this malware analysis techniques independently if you have a file, a file-system image, memory image, pcap... so it's good to **keep these actions in mind**:


malware-analysis.md

## Inspecting an Image

if you are given a **forensic image** of a device you can start **analyzing the partitions, file-system** used and **recovering** potentially **interesting files** (even deleted ones). Learn how in:


partitions-file-systems-carving/

Depending on the used OSs and even platform different interesting artifacts should be searched:


windows-forensics/


linux-forensics.md


docker-forensics.md


ios-backup-forensics.md

## Deep inspection of specific file-types and Software

If you have very **suspicious** **file**, then **depending on the file-type and software** that created it several **tricks** may be useful.\
Read the following page to learn some interesting tricks:


specific-software-file-type-tricks/

I want to do a special mention to the page:


specific-software-file-type-tricks/browser-artifacts.md

## Memory Dump Inspection


memory-dump-analysis/

## Pcap Inspection


pcap-inspection/

## **Anti-Forensic Techniques**

Keep in mind the possible use of anti-forensic techniques:


anti-forensic-techniques.md

## Threat Hunting


file-integrity-monitoring.md

## References

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/generic-methodologies-and-resources/basic-forensic-methodology/README.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
