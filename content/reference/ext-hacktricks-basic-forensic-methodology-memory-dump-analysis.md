---
title: "Memory dump analysis (HackTricks)"
category: "forensics"
subcategory: "memory-dump-analysis"
type: "reference"
tags: ["hacktricks", "forensics", "volatility", "memory-forensics", "pcap", "memory-dump-analysis", "memory", "dump", "analysis"]
summary: "Start searching for malware inside the pcap."
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/README.md"
license: "CC BY-NC 4.0"
---

# Memory dump analysis


## Start

Start **searching** for **malware** inside the pcap. Use the **tools** mentioned in [**Malware Analysis**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md).

## [Volatility](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility is an open-source framework for memory dump analysis**. This Python tool analyzes dumps from external sources or VMware VMs, identifying data like processes and passwords based on the dump's OS profile. It's extensible with plugins, making it highly versatile for forensic investigations.<sup>[[1]](#references)[[2]](#references)</sup>

[**Find here a cheatsheet**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

## Mini dump crash report

When the dump is small (just some KB, maybe a few MB), it may be a mini dump crash report rather than a full memory dump.<sup>[[3]](#references)</sup>

![Volatility - Mini dump crash report: A small dump file identified as a Mini DuMP crash report](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(532).png)

If you have Visual Studio installed, you can open this file to view basic information such as the process name, architecture, exception details, and loaded modules:<sup>[[4]](#references)</sup>

![Volatility - Mini dump crash report: If you have Visual Studio installed, you can open this file and bind some basic information like process name, architecture, exception info and...](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(263).png)

You can also inspect the exception and view the module's disassembly.<sup>[[4]](#references)</sup>

![Visual Studio minidump Actions panel with options to debug natively and set symbol paths](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(142).png)

![Visual Studio disassembly of instructions from the minidump exception](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(610).png)

Anyway, Visual Studio isn't the best tool to perform an analysis of the depth of the dump.

You should **open** it using **IDA** or **Radare** to inspection it in **depth**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility Usage](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump Files](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Use dump files in the Visual Studio debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/README.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
