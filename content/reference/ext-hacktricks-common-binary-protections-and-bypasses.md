---
title: "Common Binary Exploitation Protections & Bypasses (HackTricks)"
category: "pwn"
subcategory: "common-binary-protections-and-bypasses"
type: "reference"
tags: ["hacktricks", "pwn", "common", "binary", "exploitation", "protections", "bypasses", "common-binary-protections-and-by"]
summary: "This section groups common binary-hardening mechanisms and exploitation workflows."
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/common-binary-protections-and-bypasses/README.md"
license: "CC BY-NC 4.0"
---

# Common Binary Exploitation Protections & Bypasses


This section groups common binary-hardening mechanisms and exploitation workflows. Core dumps are especially useful while developing and debugging a bypass.

## Enable core dumps

A core dump records selected parts of a process's memory and execution state when the process terminates abnormally. It is useful for reproducing a crash and inspecting registers, mappings, and the call stack, but it can also contain secrets from process memory.<sup>[[1]](#references)</sup>

### Enable core-dump generation

The shell's soft `RLIMIT_CORE` value controls the largest core file its child processes may create. Set it to `unlimited` for the current shell and commands started from it:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ulimit -c unlimited
```

For PAM-managed login sessions, a corresponding `/etc/security/limits.conf` entry is:
```text
* soft core unlimited
```

This setting does not necessarily apply to services started by `systemd`; service limits and the kernel's `core_pattern` can redirect or suppress dumps. Check `ulimit -c`, `/proc/sys/kernel/core_pattern`, and the applicable service configuration before assuming that a file named `core` will appear.<sup>[[1]](#references)</sup>

### Analyze a core dump with GDB

Pass both the exact executable and its core dump to GDB:<sup>[[3]](#references)</sup>
```bash
gdb /path/to/executable /path/to/core_file
```

Useful first commands include `info registers`, `info proc mappings`, `bt`, and `x/i $pc`. Use the same executable and shared-library versions that produced the dump so addresses and symbols resolve correctly.

## References

- [1] [Linux `core(5)` manual page](https://man7.org/linux/man-pages/man5/core.5.html)
- [2] [GNU Bash manual - `ulimit`](https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html#index-ulimit)
- [3] [GDB manual - Files](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Files.html)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/common-binary-protections-and-bypasses/README.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
