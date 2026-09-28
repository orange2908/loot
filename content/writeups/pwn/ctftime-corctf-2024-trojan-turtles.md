---
title: "trojan-turtles - corCTF 2024"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["kernel", "paging", "pwn", "hypervisor", "kvm", "shellcode", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "Running Bindiff/Diaspora reveals backdoored handlevmread and handlevmwrite functions for nested VMX emulation from the L1 hypervisor - arbitrary OOB read/write is provided through x86 debug registers."
source:
  name: "CTFtime writeup #39362"
  url: "https://ctftime.org/writeup/39362"
original_source: "https://www.willsroot.io/2024/08/trojan-turtles.html"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "trojan-turtles"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** trojan-turtles
- **Author team:** Crusaders of Rust
- **CTFtime tags:** kernel, paging, pwn, hypervisor, kvm
- **CTFtime:** <https://ctftime.org/writeup/39362>
- **Original writeup:** <https://www.willsroot.io/2024/08/trojan-turtles.html>

---
Running Bindiff/Diaspora reveals backdoored `handle_vmread` and `handle_vmwrite` functions for nested VMX emulation from the L1 hypervisor - arbitrary OOB read/write is provided through x86 debug registers. There are many ways to compromise the L1 host at this point. My approach was to just gather enough leaks to inject a 1 GB rwx shellcode page in the L1 kernel PUD tables and hijack the function pointer located at `kvm->arch.kvmclock_update_work.work.func`.
