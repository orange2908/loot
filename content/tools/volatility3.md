---
title: "Tool - Volatility 3"
category: forensics
subcategory: memory-forensics
type: tool
tags: [volatility3, vol3, memory-forensics, ram-dump, windows, linux, pslist, malfind, netscan, dumpfiles, symbol-table, isf, hashdump, memory-triage, forensics]
summary: "The memory-forensics framework: parse a RAM dump into processes, network connections, files, registry values and injected code."
related: [forensics-triage, binwalk, wireshark-tshark]
---

## What it is

Volatility 3 parses raw memory images. Given a `.raw`/`.mem`/`.vmem`/`.dmp`, it reconstructs the OS's kernel structures and lets you list processes, open handles, network sockets, loaded modules, registry hives, console history and more. Unlike Volatility 2, it needs no manual "profile" - it downloads or builds a symbol table (ISF) automatically for Windows, and needs a matching banner/ISF for Linux and macOS.

## Install

```sh
# pipx (recommended)
pipx install volatility3
# or from source, which is what most people run
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3 && python3 -m pip install -r requirements.txt
python3 vol.py -h
# Debian/Kali package
sudo apt install volatility3
# verify (the entry point is `vol` or `vol.py` depending on the install)
vol -h | head
```

## The invocations that matter

```sh
DUMP=mem.raw

# 1. identify the OS and validate the image
vol -f "$DUMP" windows.info
vol -f "$DUMP" banners.Banners            # Linux/macOS: find the kernel banner

# 2. processes, three ways (each catches things the others miss)
vol -f "$DUMP" windows.pslist
vol -f "$DUMP" windows.pstree
vol -f "$DUMP" windows.psscan             # scans for terminated/hidden processes

# 3. command lines - often the answer is literally here
vol -f "$DUMP" windows.cmdline

# 4. console/command history
vol -f "$DUMP" windows.consoles
vol -f "$DUMP" windows.cmdscan

# 5. network
vol -f "$DUMP" windows.netscan
vol -f "$DUMP" windows.netstat

# 6. files resident in memory, then extract one
vol -f "$DUMP" windows.filescan | grep -iE 'flag|desktop|\.txt|\.png'
vol -f "$DUMP" -o out/ windows.dumpfiles --virtaddr 0xNNNNNNNN

# 7. dump a whole process's memory for reversing/strings
vol -f "$DUMP" -o out/ windows.memmap --pid 1234 --dump
vol -f "$DUMP" -o out/ windows.pslist --pid 1234 --dump      # the PE image itself

# 8. injected/suspicious code
vol -f "$DUMP" windows.malfind
vol -f "$DUMP" windows.ldrmodules
vol -f "$DUMP" windows.dlllist --pid 1234

# 9. registry
vol -f "$DUMP" windows.registry.hivelist
vol -f "$DUMP" windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
vol -f "$DUMP" windows.registry.userassist

# 10. credentials and misc
vol -f "$DUMP" windows.hashdump
vol -f "$DUMP" windows.lsadump
vol -f "$DUMP" windows.envars
vol -f "$DUMP" windows.clipboard
```

Linux dumps:
```sh
vol -f mem.lime banners.Banners           # get the exact kernel version first
vol -f mem.lime linux.pslist
vol -f mem.lime linux.bash                # bash history from memory
vol -f mem.lime linux.lsof
vol -f mem.lime linux.proc.Maps --pid 1234
vol -f mem.lime -o out/ linux.proc.Maps --pid 1234 --dump
```

Housekeeping:
```sh
# point at a custom symbol table directory
vol -s ./symbols -f "$DUMP" windows.info
# render as JSON/CSV for scripting
vol -r json -f "$DUMP" windows.pslist > pslist.json
vol -r csv  -f "$DUMP" windows.netscan > net.csv
# list every available plugin
vol -f "$DUMP" -h | grep -E '^\s+(windows|linux|mac)\.'
```

## Gotchas

- **Run `strings` first, always.** `strings -a "$DUMP" | grep -i 'flag{'` and `strings -a -e l "$DUMP" | grep -i 'flag{'` (UTF-16LE for Windows) solve a large fraction of memory challenges in five seconds.
- Volatility 3 plugin names differ completely from Volatility 2. `pslist` is `windows.pslist`; `imageinfo` no longer exists (use `windows.info`).
- Some older CTF images only work with **Volatility 2** and an explicit `--profile=`. Keep vol2 installed alongside for those.
- Symbol tables: Windows ones download automatically (needs network). For Linux/macOS you must supply an ISF built from the exact kernel's debug symbols - get the banner with `banners.Banners`, then find or build the ISF.
- `windows.filescan` lists files **referenced** in memory, not files whose contents are fully resident. `dumpfiles` may return partial data.
- A hibernation file (`hiberfil.sys`) or a crash dump needs conversion first for some plugins; vol3 handles many formats natively but not all.
- Plugins are slow on large images; run the cheap ones (`info`, `pslist`, `cmdline`) first and pipe expensive ones to a file in the background.
- `-o out/` must exist before `--dump` will write to it.
- If every plugin errors out, the image is probably not a raw memory dump - check with `file` and `binwalk`.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| vol3 cannot parse the image | Volatility 2 with an explicit profile; `Rekall` (unmaintained but still works on old images) |
| You just need artefacts fast | `bulk_extractor -o be/ mem.raw` (emails, URLs, keys, carved files) |
| File recovery from the dump | `binwalk -e`, `foremost`, `photorec` |
| Windows-specific deep dive | `MemProcFS` (mounts the dump as a filesystem - extremely convenient) |
| Only strings matter | `strings -a`, `strings -a -e l`, `grep` |
| A crash dump / minidump | `WinDbg`, or `dmp2raw`-style converters |
| Linux with no ISF available | carve `/proc`-like structures manually, or fall back to `strings` and `bulk_extractor` |
