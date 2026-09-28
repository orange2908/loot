---
title: "Memory Forensics - Volatility 3 Workflow"
category: forensics
subcategory: memory
type: technique
tags: [volatility3, vol3, volatility, memory-forensics, memory-dump, ram-dump, pslist, psscan, pstree, malfind, netscan, dumpfiles, filescan, hashdump, windows-info, isf, symbol-table, dfir, triage]
difficulty: medium
summary: "Profile-less Volatility 3 triage: windows.info, the 20 plugins that actually produce flags, and how to dump processes and files out of RAM."
when_to_use:
  - "You were handed a .raw / .mem / .vmem / .dmp / .lime / .crash file"
  - "The challenge says 'the attacker was still logged in' or 'find what was running'"
  - "strings on the dump shows Windows paths, registry keys, or PROCESS_ names"
  - "A disk image alone does not explain the incident and a RAM capture is provided"
tools: [volatility3, volatility, yara, pypykatz, bulk-extractor]
related: [memory-volatility2, memory-credential-extraction, memory-injected-code, memory-linux-and-carving]
---

## TL;DR

Volatility 3 needs no profile: it fingerprints the kernel and downloads/loads a matching **ISF**
(Intermediate Symbol Format) JSON symbol table. Run `windows.info` first to prove the image parses,
then `pstree`, `cmdline`, `netscan`, `malfind`, `filescan` in that order. Ninety percent of CTF
memory flags come out of `cmdline`, `consoles`, `filescan`+`dumpfiles`, `netscan`, or plain
`strings -el`.

## Recognise it

- File is 512 MB / 1 GB / 2 GB / 4 GB and roughly a power-of-two plus change.
- `file mem.raw` says `data`; `xxd mem.raw | head` shows mostly zeros with scattered structures.
- `strings -a mem.raw | grep -c 'C:\\Windows'` returns thousands.
- Extensions: `.raw`, `.mem`, `.vmem` (VMware), `.vmss`/`.vmsn` (VMware suspend), `.dmp`
  (Windows crash dump, header `PAGEDUMP`/`PAGEDU64`), `.lime`/`.dump` (LiME), `.aff4`, `.core`.
- `.hpak`/`.dd` from FTK Imager or DumpIt; DumpIt output is raw.

## Install

```sh
# preferred: pipx keeps volatility3 and its deps out of your system python
pipx install volatility3
# or a plain venv install (gives you the `vol` entry point)
python3 -m venv ~/.venv/vol3 && ~/.venv/vol3/bin/pip install volatility3
# or run straight from a git checkout when you need bleeding-edge plugins
git clone https://github.com/volatilityfoundation/volatility3 && cd volatility3 && pip install -r requirements.txt
# from a checkout the entry point is vol.py, not vol
python3 vol.py -h
# confirm the version and where it will look for symbols
vol --help | head -40
```

Throughout this file `vol3` means whichever of `vol`, `vol.py`, `python3 vol.py` you have. Alias it:

```sh
# one alias so every command below is copy-pasteable
alias vol3='python3 /opt/volatility3/vol.py'
```

## Workflow

### Step 0 - prove the image parses

```sh
# kernel build, DTB, symbol table used, system time: if this fails nothing else will work
vol3 -f mem.raw windows.info
# same for a Linux image (needs a matching ISF, see memory-linux-and-carving)
vol3 -f mem.raw banners.Banners
# list every plugin available to this install
vol3 -f mem.raw -h | sed -n '/plugins:/,$p'
```

`windows.info` prints `Is64Bit`, `NtMajorVersion`, `NtBuildLab`, `SystemTime`. **Write the
SystemTime down** - CTF timelines are usually anchored to it.

### Step 1 - processes

```sh
# doubly-linked list walk: fast, but a rootkit can unlink from it
vol3 -f mem.raw windows.pslist
# pool-tag scan: finds terminated and unlinked (hidden) processes
vol3 -f mem.raw windows.psscan
# parent/child tree: the fastest way to spot "winword.exe -> cmd.exe -> powershell.exe"
vol3 -f mem.raw windows.pstree
# vol3 has no psxview; diff pslist against psscan yourself
vol3 -f mem.raw -r csv windows.pslist > pslist.csv
vol3 -f mem.raw -r csv windows.psscan > psscan.csv
# PIDs present in psscan but absent from pslist are hidden or already exited
comm -13 <(cut -d, -f3 pslist.csv | sort -u) <(cut -d, -f3 psscan.csv | sort -u)
```

### Step 2 - what was typed and what was run

```sh
# full command lines including arguments: encoded powershell lives here
vol3 -f mem.raw windows.cmdline
# scrollback of every console (conhost) buffer: input AND output
vol3 -f mem.raw windows.consoles
# environment variables per process: PATH, TEMP, and sometimes the flag
vol3 -f mem.raw windows.envars
# token/SID per process: shows privilege escalation to SYSTEM
vol3 -f mem.raw windows.getsids --pid 1234
```

`windows.cmdline` is the single highest-yield plugin in CTF memory challenges. Grep it:

```sh
# base64-encoded PowerShell, the classic
vol3 -f mem.raw windows.cmdline | grep -iE '(-enc|-e |frombase64string|iex|downloadstring)'
```

### Step 3 - network

```sh
# TCP/UDP endpoints and their owning PIDs (Vista+ pool scan)
vol3 -f mem.raw windows.netscan
# live-list version, cleaner output, fewer stale entries (Win10+)
vol3 -f mem.raw windows.netstat
# just the established connections to non-RFC1918 addresses
vol3 -f mem.raw windows.netscan | grep ESTABLISHED | grep -vE '(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
```

### Step 4 - injected code

```sh
# private, executable, non-file-backed VADs plus a disassembly preview
vol3 -f mem.raw windows.malfind
# same but write every hit to disk for further analysis
vol3 -f mem.raw -o ./dumps windows.malfind --dump
# loaded modules per process: a DLL from \Temp\ is a finding
vol3 -f mem.raw windows.dlllist --pid 1234
# VAD map with protections: look for PAGE_EXECUTE_READWRITE + Private
vol3 -f mem.raw windows.vadinfo --pid 1234
```

### Step 5 - files and registry

```sh
# every FILE_OBJECT in the pool: this is your "ls" of the RAM
vol3 -f mem.raw windows.filescan > filescan.txt
# find the interesting ones
grep -iE '\.(zip|rar|7z|png|jpg|pdf|docx?|xlsx?|txt|ps1|bat|vbs|exe|dll|kdbx|sqlite)$' filescan.txt
# dump one file by its FILE_OBJECT virtual address (first column of filescan)
vol3 -f mem.raw -o ./dumps windows.dumpfiles --virtaddr 0x8e1d2a3b4c50
# or dump everything a process has open
vol3 -f mem.raw -o ./dumps windows.dumpfiles --pid 1234
# registry hives that were loaded in memory
vol3 -f mem.raw windows.registry.hivelist
# read a key out of RAM without ever touching the disk image
vol3 -f mem.raw windows.registry.printkey --key 'Microsoft\Windows\CurrentVersion\Run'
# scan for hives the hivelist missed
vol3 -f mem.raw windows.registry.hivescan
# MFT records that happened to be cached in RAM
vol3 -f mem.raw windows.mftscan.MFTScan
```

### Step 6 - dump a process and analyse it offline

```sh
# dump the PE image of one process (writes pid.<pid>.<base>.dmp into -o)
vol3 -f mem.raw -o ./dumps windows.pslist --pid 1234 --dump
# dump the FULL address space of that process (much bigger, includes heap/stack)
vol3 -f mem.raw -o ./dumps windows.memmap --pid 1234 --dump
# then hunt inside it with normal tools
strings -a -el ./dumps/pid.1234.dmp | grep -aoE 'flag\{[^}]+\}'
binwalk -e ./dumps/pid.1234.dmp
```

## The twenty plugins that matter

| Plugin | What it gives you |
| --- | --- |
| `windows.info` | Kernel build, arch, system time - always run first |
| `windows.pslist` | Live process list (EPROCESS list walk) |
| `windows.psscan` | Pool-scanned processes incl. exited/hidden |
| `windows.pstree` | Parent-child tree - anomaly hunting |
| `windows.cmdline` | Full command lines, encoded payloads |
| `windows.consoles` | conhost scrollback: typed commands + output |
| `windows.cmdscan` | Command history buffers (older builds) |
| `windows.envars` | Per-process environment variables |
| `windows.getsids` | Token SIDs - who the process ran as |
| `windows.dlllist` | Loaded modules per process |
| `windows.handles` | Open handles: files, keys, mutexes, events |
| `windows.filescan` | Every FILE_OBJECT - the RAM directory listing |
| `windows.dumpfiles` | Extract cached file contents to disk |
| `windows.memmap` | Page map; `--dump` gives the full process space |
| `windows.netscan` | TCP/UDP endpoints + owning PID |
| `windows.netstat` | Connection list from the live structures |
| `windows.malfind` | Injected/private executable memory |
| `windows.vadinfo` / `windows.vadwalk` | VAD tree, protections, mapped file |
| `windows.svcscan` | Windows services incl. their binary paths |
| `windows.registry.hivelist` / `printkey` | Registry straight out of RAM |
| `windows.hashdump` / `lsadump` / `cachedump` | Credential material |
| `windows.modules` / `windows.modscan` | Kernel drivers (list vs scan = rootkit gap) |
| `windows.ssdt` / `windows.callbacks` / `windows.driverscan` | Kernel hooking |
| `windows.clipboard` | Last clipboard contents |
| `windows.sessions` | Logon sessions and their processes |
| `timeliner.Timeliner` | Everything with a timestamp, merged |

```sh
# merge every timestamped artefact into one CSV for a super-timeline
vol3 -f mem.raw -r csv timeliner.Timeliner > mem_timeline.csv
# yara over process memory (vol3 name; needs yara-python)
vol3 -f mem.raw windows.vadyarascan --yara-rules 'flag{'
# yara over the whole physical space
vol3 -f mem.raw yarascan.YaraScan --yara-rules 'flag{'
```

## Output renderers

```sh
# machine-readable, the one you want for scripting
vol3 -f mem.raw -r json windows.pslist > pslist.json
# spreadsheet-friendly
vol3 -f mem.raw -r csv windows.netscan > netscan.csv
# indented tree rendering (pstree looks much better with this)
vol3 -f mem.raw -r pretty windows.pstree
# quiet the progress bar when piping
vol3 -q -f mem.raw windows.pslist
```

## Symbol table troubleshooting

```sh
# vol3 caches downloaded ISF files here
ls ~/.cache/volatility3/
# point it at an offline symbol pack (unzip the windows/linux/mac symbol bundles here)
vol3 --symbol-dirs /opt/volatility3/volatility3/symbols -f mem.raw windows.info
# clear a poisoned cache when you get "unsatisfied requirement kernel"
rm -rf ~/.cache/volatility3/*
# fully offline: pre-seed symbols from the official symbol zips
mkdir -p /opt/volatility3/volatility3/symbols && cd $_ && unzip ~/Downloads/windows.zip
```

Common failures:

- `Unsatisfied requirement plugins.PsList.kernel` - no symbol table matched. The dump is truncated,
  it is not the OS you think, or you need the PDB for that exact build.
- `No suitable requirements fulfilled` - usually a crash dump/hibernation file; convert first.
- Extremely slow scans - the image is on a network share, or you are scanning a 16 GB dump. Use
  `--single-location file:///abs/path` and local disk.

## Code

```python
#!/usr/bin/env python3
"""vol3 triage driver: run a handful of plugins with -r json, parse, and print a report.

Usage:
    python3 vol3_triage.py mem.raw [/path/to/vol]

Works with any volatility3 that supports `-r json`. Falls back gracefully when a
plugin is unavailable for the image (e.g. Linux dumps have no windows.* plugins).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Any

SUSPICIOUS_PARENTS = {
    "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "outlook.exe": {"cmd.exe", "powershell.exe", "wscript.exe"},
    "explorer.exe": {"powershell.exe"},
    "w3wp.exe": {"cmd.exe", "powershell.exe"},
    "services.exe": set(),
}
EXPECTED_PARENT = {
    "svchost.exe": "services.exe",
    "lsass.exe": "wininit.exe",
    "services.exe": "wininit.exe",
    "smss.exe": "System",
    "csrss.exe": "smss.exe",
    "wininit.exe": "smss.exe",
    "winlogon.exe": "smss.exe",
}
BAD_PATH_HINTS = ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\", "\\programdata\\")


def run_plugin(vol: str, image: str, plugin: str, extra: list[str] | None = None) -> list[dict[str, Any]]:
    """Run one vol3 plugin with the JSON renderer and return its rows."""
    cmd = [vol, "-q", "-r", "json", "-f", image, plugin] + (extra or [])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[!] {plugin}: {exc}", file=sys.stderr)
        return []
    if proc.returncode != 0:
        first = (proc.stderr or "").strip().splitlines()[:1]
        print(f"[!] {plugin} failed: {first[0] if first else 'unknown error'}", file=sys.stderr)
        return []
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        print(f"[!] {plugin}: output was not JSON", file=sys.stderr)
        return []
    return data if isinstance(data, list) else []


def get(row: dict[str, Any], *names: str, default: Any = "") -> Any:
    """vol3 column names drift between versions; try several."""
    for n in names:
        if n in row and row[n] not in (None, ""):
            return row[n]
    return default


def report_processes(pslist: list[dict], psscan: list[dict]) -> None:
    by_pid = {}
    for r in pslist:
        by_pid[int(get(r, "PID", default=0))] = str(get(r, "ImageFileName", "Name"))
    print("== process anomalies ==")
    live = {int(get(r, "PID", default=0)) for r in pslist}
    scanned = {int(get(r, "PID", default=0)) for r in psscan}
    hidden = sorted(p for p in scanned - live if p)
    if hidden:
        print(f"  [!] in psscan but not pslist (hidden/exited): {hidden}")
    for r in pslist:
        name = str(get(r, "ImageFileName", "Name")).lower()
        ppid = int(get(r, "PPID", default=0))
        parent = by_pid.get(ppid, "?").lower()
        expected = EXPECTED_PARENT.get(name)
        if expected and parent not in (expected.lower(), "?"):
            print(f"  [!] {name} (pid {get(r, 'PID')}) parent is {parent}, expected {expected}")
        children = SUSPICIOUS_PARENTS.get(parent)
        if children and name in children:
            print(f"  [!] {parent} spawned {name} (pid {get(r, 'PID')})")


def report_cmdline(rows: list[dict]) -> None:
    print("== command lines of interest ==")
    needles = ("-enc", "-encodedcommand", "frombase64string", "iex", "downloadstring",
               "certutil", "bitsadmin", "rundll32", "regsvr32", "mshta", "wscript",
               "vssadmin", "bcdedit", "-nop", "-w hidden", "invoke-")
    for r in rows:
        line = str(get(r, "Args", "CmdLine", default=""))
        low = line.lower()
        if any(n in low for n in needles) or any(h in low for h in BAD_PATH_HINTS):
            print(f"  pid {get(r, 'PID')}: {line[:300]}")


def report_net(rows: list[dict]) -> None:
    print("== external network endpoints ==")
    private = ("127.", "10.", "192.168.", "0.0.0.0", "::", "169.254.")
    for r in rows:
        fa = str(get(r, "ForeignAddr", "Foreign Addr", default=""))
        if not fa or fa.startswith(private):
            continue
        print(f"  {get(r, 'Proto', 'Protocol')} {get(r, 'LocalAddr')}:{get(r, 'LocalPort')}"
              f" -> {fa}:{get(r, 'ForeignPort')} {get(r, 'State', default='')}"
              f" pid={get(r, 'PID')} {get(r, 'Owner', default='')}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    image = sys.argv[1]
    vol = sys.argv[2] if len(sys.argv) > 2 else (shutil.which("vol") or shutil.which("vol.py") or "vol")
    info = run_plugin(vol, image, "windows.info")
    if info:
        for r in info:
            print(f"{get(r, 'Variable')}: {get(r, 'Value')}")
    pslist = run_plugin(vol, image, "windows.pslist")
    psscan = run_plugin(vol, image, "windows.psscan")
    if pslist or psscan:
        report_processes(pslist, psscan)
    report_cmdline(run_plugin(vol, image, "windows.cmdline"))
    report_net(run_plugin(vol, image, "windows.netscan"))
    mal = run_plugin(vol, image, "windows.malfind")
    if mal:
        print("== malfind hits ==")
        seen = set()
        for r in mal:
            key = (get(r, "PID"), get(r, "Process"))
            if key in seen:
                continue
            seen.add(key)
            print(f"  pid {key[0]} {key[1]} start={get(r, 'Start VPN', 'Start')}"
                  f" prot={get(r, 'Protection')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Hibernation files and crash dumps**: vol3 reads `hiberfil.sys` and `.dmp` through its layer
  stack in most builds; if not, convert with vol2 `imagecopy -O out.raw` or `hibr2bin`.
- **VMware**: analyse the `.vmem` directly; pair it with the `.vmsn` for a full snapshot.
- **Truncated dumps** produce plausible-but-wrong output. If `windows.info` system time is absurd,
  stop and re-check the file size against the VM's RAM.
- **`--pid` accepts multiple values**: `--pid 1234 5678`.
- **Do not skip strings.** `strings -a -el mem.raw | grep -aoE 'flag\{[^}]+\}'` solves a
  surprising number of "memory forensics" challenges in 10 seconds. UTF-16LE (`-el`) matters
  because Windows stores most text that way.
- Plugin names are case-sensitive and dotted: `windows.registry.printkey`, not `printkey`.
- vol3 writes dumps into the current directory unless you pass `-o DIR`.

## Tools

`volatility3`, `volatility` (2.x, see the companion file), `pypykatz`, `bulk_extractor`,
`yara`, `strings`, `binwalk`, `MemProcFS` (mount a dump as a filesystem), `Rekall` (archived).

## References

- Volatility Foundation documentation shipped with the source tree (`doc/`).
- `vol3 -h` and `vol3 -f img <plugin> -h` are authoritative for your exact version.
