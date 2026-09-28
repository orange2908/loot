---
title: "Cobalt Strike Analyze (Forensics)"
category: "forensics"
subcategory: "aes"
type: "technique"
tags: ["my-notes", "personal", "aes", "cobalt", "strike", "analyze", "forensics"]
summary: "Personal note: Cobalt Strike Analyze (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Cobalt Strike Analyze.md"
---

### Tool

> **Info** Cobalt Strike Tools
> This is a collection of Cobalt Strike tools for blue teams. All these tools can also be found on GitHub and in my DidierStevensSuite.zip file. Remark that these tools not only have an help option (-h), but also come with an embedded man page: -m. 1768.py This is a tool to analyze Cobalt Strike beacons....  
> [https://blog.didierstevens.com/programs/cobalt-strike-tools/](https://blog.didierstevens.com/programs/cobalt-strike-tools/)  

### Run

```
python ~/Desktop/tools/forensics/analyze-Cobalt-Strike-beacons/1768.py output/dll/00000169.dll
```

### Quickpost: Decrypting Cobalt Strike Traffic

> **Info** Quickpost: Decrypting Cobalt Strike Traffic
> I have been looking at several samples of Cobalt Strike beacons used in malware attacks. Although work is still ongoing, I already want to share my findings. Cobalt Strike beacons communicating over HTTP encrypt their data with AES (unless a trial version is used). I found code to decrypt/encrypt such data in the PyBeacon and...  
> [https://blog.didierstevens.com/2021/04/26/quickpost-decrypting-cobalt-strike-traffic/](https://blog.didierstevens.com/2021/04/26/quickpost-decrypting-cobalt-strike-traffic/)  

> **Info** Cobalt Strike: Using Process Memory To Decrypt Traffic - Part 3
> We decrypt Cobalt Strike traffic with cryptographic keys extracted from process memory. This series of blog posts describes different methods to decrypt Cobalt Strike traffic. In part 1 of this series, we revealed private encryption keys found in rogue Cobalt Strike packages. And in part 2, we decrypted Cobalt Strike traffic starting with a private...  
> [https://blog.nviso.eu/2021/11/03/cobalt-strike-using-process-memory-to-decrypt-traffic-part-3/](https://blog.nviso.eu/2021/11/03/cobalt-strike-using-process-memory-to-decrypt-traffic-part-3/)

---

*From your own notes: `Forensics/Cobalt Strike Analyze.md`*
