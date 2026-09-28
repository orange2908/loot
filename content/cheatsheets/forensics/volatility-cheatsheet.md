---
title: "Volatility Cheatsheet - vol3 and vol2 Side by Side"
category: forensics
subcategory: memory
type: cheatsheet
tags: [volatility3, vol3, volatility, vol2, vol-py, memory-forensics, memory-dump, ram-dump, pslist, psscan, pstree, malfind, netscan, dumpfiles, hashdump, yarascan, isf, profile, plugins, dfir]
summary: "Every Volatility plugin worth knowing with its exact vol3 and vol2 command line, a 60-plus row plugin translation table, triage greps and a troubleshooting section."
tools: [volatility3, volatility, yara, pypykatz, strings, jq]
related: [memory-volatility3-workflow, memory-volatility2, memory-credential-extraction, memory-injected-code, memory-linux-and-carving]
---

`vol3` = whichever of `vol` / `vol.py` / `python3 vol.py` you installed. `vol.py` = Volatility 2.6
under Python 2; every vol2 line needs `--profile=`. vol3 needs none, it resolves ISF symbols.

## Install and invocation

```sh
# vol3 via pipx keeps it and its deps off the system python; gives you the `vol` binary
pipx install volatility3
# vol3 from a git checkout when you need unreleased plugins, then alias it
git clone https://github.com/volatilityfoundation/volatility3 /opt/volatility3 && alias vol3='python3 /opt/volatility3/vol.py'
# vol2 without python2 on your host: container, cwd mounted at /data
docker run --rm -it -v "$PWD":/data phocean/volatility -f /data/mem.raw imageinfo
# list every plugin vol3 knows about instead of guessing names
vol3 -h | sed -n '/plugins:/,$p'
```

## Image identification

```sh
# vol3: fingerprint the kernel, prove the image parses, print DTB/KDBG/build/time
vol3 -f mem.raw windows.info
# vol2 equivalent: scans KDBG signatures and suggests profiles (slow, minutes)
vol.py -f mem.raw imageinfo
# Windows crash dump header fields (PAGEDUMP / PAGEDU64) before wasting time on it
vol3 -f mem.dmp windows.crashinfo
# no-volatility sanity check plus the UTF-16LE flag grep Windows data actually lives in
strings -el mem.raw | grep -aoE 'flag\{[^}]+\}' | sort -u
```

## Processes

```sh
# list processes by walking the EPROCESS doubly-linked list (fast, misses unlinked procs)
vol3 -f mem.raw windows.pslist
# vol2 equivalent (needs a profile)
vol.py -f mem.raw --profile=Win7SP1x64 pslist
# pool-tag scan for EPROCESS objects: finds terminated and DKOM-unlinked processes
vol3 -f mem.raw windows.psscan
# vol2 equivalent
vol.py -f mem.raw --profile=Win7SP1x64 psscan
# parent/child tree - best first view; spot cmd.exe hanging off winword.exe
vol3 -f mem.raw windows.pstree
# vol2 equivalent
vol.py -f mem.raw --profile=Win7SP1x64 pstree
# vol2 only: cross-reference five listing sources, a False column means the proc is hiding
vol.py -f mem.raw --profile=Win7SP1x64 psxview
# token SIDs: shows privilege level and group membership of the process
vol3 -f mem.raw windows.getsid --pid 1234
```

## Command lines and console

```sh
# highest-yield CTF plugin: full command line of every process, read from the PEB
vol3 -f mem.raw windows.cmdline
# vol2 equivalent
vol.py -f mem.raw --profile=Win7SP1x64 cmdline
# conhost/csrss scrollback: everything typed AND printed in cmd.exe and powershell
vol3 -f mem.raw windows.consoles
# vol2 equivalent
vol.py -f mem.raw --profile=Win7SP1x64 consoles
```

## DLLs and handles

```sh
# loaded modules per process from the PEB loader lists, with full on-disk paths
vol3 -f mem.raw windows.dlllist --pid 1234
# compare the three PEB loader lists; a module missing from one of them is hidden
vol3 -f mem.raw windows.ldrmodules --pid 1234
# every open handle (files, keys, mutants, events) - grep it for the flag path
vol3 -f mem.raw windows.handles --pid 1234
# named mutexes - malware families are often identified by one hardcoded mutant name
vol3 -f mem.raw windows.mutantscan
```

## Memory dumping and extraction

```sh
# rebuild the on-disk PE of a process from its mapped image
vol3 -f mem.raw -o ./out windows.pslist --pid 1234 --dump
# vol2 equivalent: writes executable.1234.exe into the dump dir
vol.py -f mem.raw --profile=Win7SP1x64 procdump -p 1234 -D ./out
# dump the full addressable memory of one process - this is what you strings and binwalk
vol3 -f mem.raw -o ./out windows.memmap --pid 1234 --dump
# vol2 equivalent
vol.py -f mem.raw --profile=Win7SP1x64 memdump -p 1234 -D ./out
# VAD regions with protections; PAGE_EXECUTE_READWRITE with no mapped file = injected
vol3 -f mem.raw windows.vadinfo --pid 1234
# dump one VAD by base address: the surgical way to carve injected shellcode
vol3 -f mem.raw -o ./out windows.vadinfo --pid 1234 --address 0x2a0000 --dump
```

## Files

```sh
# pool-scan for FILE_OBJECTs: every path the kernel cached, deleted files included
vol3 -f mem.raw windows.filescan
# vol2 equivalent
vol.py -f mem.raw --profile=Win7SP1x64 filescan
# dump one file by the physical offset filescan reported
vol3 -f mem.raw -o ./out windows.dumpfiles --physaddr 0x7e410f20
# dump every cached file whose name matches a regex - fastest path to the flag file
vol3 -f mem.raw -o ./out windows.dumpfiles --filter 'flag'
# MFT records still resident in RAM: filenames plus MACB timestamps
vol3 -f mem.raw windows.mftscan.MFTScan
```

## Registry

```sh
# every loaded hive with its virtual offset - always run this before printkey
vol3 -f mem.raw windows.registry.hivelist
# print one key and its values; drop --key to list the hive roots
vol3 -f mem.raw windows.registry.printkey --key 'Microsoft\Windows\CurrentVersion\Run'
# vol2 equivalent, -K is the key path and -o restricts it to one hive
vol.py -f mem.raw --profile=Win7SP1x64 printkey -K 'Microsoft\Windows\CurrentVersion\Run'
# recurse a whole subtree, which is vol3's replacement for vol2 hivedump
vol3 -f mem.raw windows.registry.printkey --key 'ControlSet001\Services' --recurse
```

## Credentials

```sh
# local NT hashes from SAM+SYSTEM, ready for hashcat -m 1000
vol3 -f mem.raw windows.hashdump
# LSA secrets: DPAPI keys, service account passwords, the autologon password
vol3 -f mem.raw windows.lsadump
# dump lsass memory, because plaintexts need pypykatz not volatility
vol3 -f mem.raw -o ./out windows.memmap --pid "$(vol3 -f mem.raw windows.pslist|awk '/lsass.exe/{print $1}')" --dump
# pypykatz on that dump: wdigest, kerberos and msv plaintext/NT material
pypykatz lsa minidump ./out/pid.*.dmp
# vol2 only: recover a TrueCrypt master key still resident in the driver
vol.py -f mem.raw --profile=Win7SP1x64 truecryptmaster
```

## Network

```sh
# pool-scan for every TCP/UDP endpoint and connection, Vista through Win11
vol3 -f mem.raw windows.netscan
# vol3: walk the live connection tables instead of scanning, fewer false positives
vol3 -f mem.raw windows.netstat
# vol2 XP/2003 only: active connections, closed-connection scan, listening sockets
vol.py -f mem.raw --profile=WinXPSP3x86 connections; vol.py -f mem.raw --profile=WinXPSP3x86 sockets
# only the external live sockets - the C2 address is almost always in this list
vol3 -f mem.raw windows.netscan | grep -E 'ESTABLISHED|LISTENING' | grep -vE ' 127\.| 0\.0\.0\.0| ::1'
```

## Injection and rootkits

```sh
# the injected-code plugin: private RWX VADs with no backing file, plus a disassembly peek
vol3 -f mem.raw windows.malfind
# same but writing every suspicious region to disk for static analysis
vol3 -f mem.raw -o ./out windows.malfind --dump
# processes whose in-memory PE header disagrees with the backing file (hollowing)
vol3 -f mem.raw windows.hollowprocesses
# threads whose start address is not inside any mapped module
vol3 -f mem.raw windows.suspicious_threads
# vol2 only: inline, IAT and EAT hook detection across user and kernel space
vol.py -f mem.raw --profile=Win7SP1x64 apihooks
# services from registry plus in-memory records; a ServiceDll in Temp is your answer
vol3 -f mem.raw windows.svcscan
```

## Kernel

```sh
# loaded kernel drivers from PsLoadedModuleList
vol3 -f mem.raw windows.modules
# IRP major function tables; an entry pointing outside its driver is a hook
vol3 -f mem.raw windows.driverirp
# SSDT: any entry outside ntoskrnl/win32k is a system call hook
vol3 -f mem.raw windows.ssdt
# process/thread/image-load notification callbacks - classic rootkit persistence
vol3 -f mem.raw windows.callbacks
# drivers loaded and then unloaded: the rootkit that cleaned up after itself
vol3 -f mem.raw windows.unloadedmodules
```

## User activity (vol2 only)

```sh
# UserAssist: GUI-launched program names and run counts, ROT13-decoded by the plugin
vol.py -f mem.raw --profile=Win7SP1x64 userassist
# ShellBags: every folder browsed in Explorer, including deleted and removable paths
vol.py -f mem.raw --profile=Win7SP1x64 shellbags
# ShimCache from the registry: executables that existed on disk, with timestamps
vol.py -f mem.raw --profile=Win7SP1x64 shimcache
# IE / WinINet URL history records carved out of memory
vol.py -f mem.raw --profile=Win7SP1x64 iehistory
# clipboard contents, because people paste passwords and flags
vol.py -f mem.raw --profile=Win7SP1x64 clipboard
```

## Linux

```sh
# vol3 Linux wants an ISF built from that exact kernel's debug symbols, not a profile
vol3 -f mem.lime linux.pslist
# vol2 wants a profile zip dropped into volatility/plugins/overlays/linux/
vol.py -f mem.lime --profile=LinuxUbuntu1804x64 linux_pslist
# bash history recovered from the heap of every bash process - top Linux CTF plugin
vol3 -f mem.lime linux.bash
# loaded kernel modules and a syscall-table hook check
vol3 -f mem.lime linux.lsmod && vol3 -f mem.lime linux.check_syscall
# build an ISF yourself when no ready-made symbol pack exists for that kernel
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-5.4.0-42-generic > ~/.cache/volatility3/ubuntu-5.4.0-42.json
```

## Mac

```sh
# process list from the kernel allproc list
vol3 -f mac.mem mac.pslist
# loaded kernel extensions and per-process sockets
vol3 -f mac.mem mac.lsmod && vol3 -f mac.mem mac.netstat
# vol2 equivalent process list (needs a Mac profile zip)
vol.py -f mac.mem --profile=MacSierra_10_12_6x64 mac_pslist
# vol2 only: recover keychain master key material
vol.py -f mac.mem --profile=MacSierra_10_12_6x64 mac_keychaindump
```

## Timelines and YARA

```sh
# one merged timeline from every plugin that exposes a timestamp
vol3 -r csv -f mem.raw timeliner.Timeliner > mem_timeline.csv
# vol2 equivalent as a body file, then render it with mactime
vol.py -f mem.raw --profile=Win7SP1x64 timeliner --output=body --output-file=mem.body && mactime -b mem.body -d > tl.csv
# one-off string scan with no rule file to write
vol3 -f mem.raw yarascan.YaraScan --yara-string 'flag{'
# scan only process VAD space so the hit comes back with an owning PID
vol3 -f mem.raw windows.vadyarascan --yara-string 'flag{'
# vol2 equivalents: -Y inline string, -y rules file, -D dumps each hit region
vol.py -f mem.raw --profile=Win7SP1x64 yarascan -y rules.yar -D ./hits
```

## Output renderers

```sh
# vol3 renderers are pretty (default), quick, csv, json, jsonl - csv/json are scriptable
vol3 -r csv -f mem.raw windows.pslist
# JSON into jq so you filter on a named field instead of guessing awk column numbers
vol3 -r json -f mem.raw windows.netscan | jq -r '.[]|select(.State=="ESTABLISHED")|"\(.ForeignAddr):\(.ForeignPort)"'
# -q silences the progress bar so redirection produces a clean file
vol3 -q -r csv -f mem.raw windows.filescan > filescan.csv
# vol2 renderers: text, csv, json, sqlite, body, html - sqlite lets you SQL-join plugins
vol.py -f mem.raw --profile=Win7SP1x64 pslist --output=sqlite --output-file=vol.db
```

## vol2 to vol3 plugin translation

| vol2 | vol3 | What it does |
|---|---|---|
| `imageinfo` | `windows.info` | Kernel build, DTB, KDBG, image time |
| `kdbgscan` | folded into `windows.info` | Locate the kernel debugger block |
| `kpcrscan` | folded into `windows.info` | Locate per-CPU KPCR blocks |
| `pslist` | `windows.pslist` | Processes via the EPROCESS list |
| `psscan` | `windows.psscan` | Processes via pool-tag scan |
| `pstree` | `windows.pstree` | Parent/child process tree |
| `psxview` | no direct equivalent | Cross-view hidden process detection |
| `dlllist` | `windows.dlllist` | Loaded modules per process |
| `dlldump` | `windows.dlllist --dump` | Write mapped DLLs to disk |
| `ldrmodules` | `windows.ldrmodules` | Three-PEB-list diff for hidden DLLs |
| `handles` | `windows.handles` | Open kernel object handles |
| `getsids` | `windows.getsid` | Token SIDs per process |
| `privs` | `windows.privileges` | Token privileges per process |
| `cmdline` | `windows.cmdline` | Process command lines from the PEB |
| `cmdscan` | `windows.consoles` | Console command history ring buffer |
| `consoles` | `windows.consoles` | Console input and output scrollback |
| `consolescan` | `windows.consoles` | Pool-scan variant of consoles |
| `envars` | `windows.envars` | Per-process environment block |
| `verinfo` | `windows.verinfo` | PE version resources of mapped modules |
| `memmap` | `windows.memmap` | Virtual-to-physical page map |
| `memdump` | `windows.memmap --dump` | Dump all of a process's memory |
| `procdump` | `windows.pslist --dump` | Rebuild the process PE to disk |
| `vadinfo` / `vadtree` | `windows.vadinfo` | VAD tree, protections, mapped files |
| `vadwalk` | `windows.vadwalk` | Raw VAD node walk |
| `vaddump` | `windows.vadinfo --dump` | Dump VAD regions to files |
| `malfind` | `windows.malfind` | Private RWX regions = injected code |
| `apihooks` | `windows.iat` (partial) | Inline / IAT / EAT hook detection |
| `filescan` | `windows.filescan` | Pool-scan for FILE_OBJECTs |
| `dumpfiles` | `windows.dumpfiles` | Extract cached file contents |
| `mftparser` | `windows.mftscan.MFTScan` | Resident MFT records |
| `hivelist` | `windows.registry.hivelist` | Loaded registry hives |
| `hivedump` | `windows.registry.printkey --recurse` | Dump a whole hive subtree |
| `printkey` | `windows.registry.printkey` | Print one key and its values |
| `hashdump` | `windows.hashdump` | Local NT hashes from SAM |
| `lsadump` | `windows.lsadump` | LSA secrets |
| `cachedump` | `windows.cachedump` | Domain cached credentials |
| `userassist` | vol2 only | GUI program execution counts |
| `shellbags` | vol2 only | Explorer folder browsing history |
| `shimcache` | `windows.shimcachemem` | AppCompatCache execution evidence |
| `iehistory` | vol2 only | IE / WinINet URL history |
| `clipboard` | vol2 only | Clipboard contents |
| `screenshot` | vol2 only | ASCII desktop reconstruction |
| `evtlogs` | vol2 only (XP/2003) | Parsed .evt event log records |
| `connections` | `windows.netstat` | XP/2003 active TCP connections |
| `connscan` | `windows.netscan` | XP/2003 connection pool scan |
| `sockets` / `sockscan` | `windows.netscan` | XP/2003 sockets |
| `netscan` | `windows.netscan` | Vista+ TCP/UDP endpoints |
| `svcscan` | `windows.svcscan` | Windows services |
| `getservicesids` | `windows.getservicesids` | Service name to SID mapping |
| `modules` | `windows.modules` | Loaded kernel drivers |
| `modscan` | `windows.modscan` | Pool-scan for drivers |
| `moddump` | `windows.modules --dump` | Dump a driver to disk |
| `driverscan` | `windows.driverscan` | DRIVER_OBJECT pool scan |
| `driverirp` | `windows.driverirp` | IRP major function tables |
| `devicetree` | `windows.devicetree` | Device stack and attached filters |
| `unloadedmodules` | `windows.unloadedmodules` | Drivers loaded then unloaded |
| `ssdt` | `windows.ssdt` | System service table hooks |
| `callbacks` | `windows.callbacks` | Kernel notification routines |
| `mutantscan` | `windows.mutantscan` | Named mutex objects |
| `thrdscan` / `threads` | `windows.thrdscan` / `windows.threads` | ETHREAD scan, thread start addresses |
| `sessions` | `windows.sessions` | Logon sessions and their processes |
| `symlinkscan` | `windows.symlinkscan` | Object-manager symbolic links |
| `bigpools` / `pooltracker` | `windows.bigpools` / `windows.poolscanner` | Large pool allocations, pool tags |
| `yarascan` | `yarascan.YaraScan` | YARA over physical memory |
| `timeliner` | `timeliner.Timeliner` | Merged artifact timeline |
| `mbrparser` | `windows.mbrscan` | Master boot record recovery |
| `crashinfo` | `windows.crashinfo` | Crash dump header fields |
| `truecryptmaster` | vol2 only | TrueCrypt master key from RAM |
| `linux_pslist` | `linux.pslist` | Linux process list |
| `linux_bash` | `linux.bash` | Recovered bash history |
| `mac_pslist` | `mac.pslist` | macOS process list |

## Triage one-liners

```sh
# the living-off-the-land binaries, straight out of the process tree
vol3 -f mem.raw windows.pstree | grep -Ei 'cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil'
# encoded PowerShell in a command line - the single most common CTF artefact
vol3 -f mem.raw windows.cmdline | grep -Ei '\-enc|frombase64string|iex|downloadstring|hidden'
# the flag out of any plugin output, generic brace form
vol3 -f mem.raw windows.consoles | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
# the flag straight out of raw memory in both encodings
strings -a mem.raw | grep -aoE 'flag\{[^}]+\}'; strings -el mem.raw | grep -aoE 'flag\{[^}]+\}'
# every unique external IP the box talked to
vol3 -f mem.raw windows.netscan | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | grep -vE '^(10\.|127\.|192\.168\.|0\.0)'
```

## Dump everything

```sh
# run the high-yield plugins in one pass, one output file each
for p in windows.info windows.pstree windows.cmdline windows.consoles windows.netscan windows.malfind windows.svcscan windows.filescan; do vol3 -q -f mem.raw "$p" > "out_${p}.txt" 2>/dev/null; done
# dump every cached file object volatility can reconstruct (expect thousands, expect failures)
mkdir -p allfiles && vol3 -f mem.raw -o ./allfiles windows.dumpfiles
# dump the full memory of every process, one file per PID
mkdir -p procs && for pid in $(vol3 -q -r csv -f mem.raw windows.pslist|tail -n +2|cut -d, -f2); do vol3 -f mem.raw -o ./procs windows.memmap --pid "$pid" --dump; done
# one flag grep across every artefact you just produced
grep -raoiE '[a-z0-9_]+\{[^}]{4,80}\}' out_*.txt allfiles/ procs/ | sort -u
```

## When it breaks

```sh
# "Unsatisfied requirement plugins.X.kernel" - first confirm what the file actually is
file mem.raw && xxd -l 16 mem.raw
# crash dump or hibernation file: convert it to raw with vol2 imagecopy first
vol.py -f mem.dmp --profile=Win7SP1x64 imagecopy -O mem.raw
# hibernation file metadata (compressed, needs conversion before vol3 will touch it)
vol.py -f hiberfil.sys --profile=Win7SP1x64 hibinfo
# vol3 caches downloaded ISF symbol packs here; clear it when a pack is corrupt
ls -la ~/.cache/volatility3/ && rm -rf ~/.cache/volatility3/*
# offline: unpack symbol packs yourself and point vol3 at the directory
mkdir -p /opt/symbols/windows && unzip windows.zip -d /opt/symbols/windows
# --symbol-dirs is how you use those symbols with no internet access
vol3 --symbol-dirs /opt/symbols -f mem.raw windows.info
# vol2 "No suitable address space mapping found" = wrong profile, re-scan for the KDBG
vol.py -f mem.raw kdbgscan | grep -E 'Profile suggestion|KdCopyDataBlock'
# force both the KDBG and the DTB when vol2 keeps picking the wrong CPU's block
vol.py -f mem.raw --profile=Win7SP1x64 --kdbg=0xf80002c440a0 --dtb=0x187000 pslist
# plugin errors mid-run: rerun verbose and read the last frame of the traceback
vol3 -vvv -f mem.raw windows.netscan 2>&1 | tail -30
# nothing parses at all: treat it as a flat file and carve it
bulk_extractor -o be_out mem.raw && foremost -i mem.raw -o carved
```

## References

- Volatility 3 documentation and built-in plugin listing (`vol3 -h`)
- Volatility 2.6 command reference wiki
- `dwarf2json` for building Linux and Mac ISF symbol tables
- `pypykatz` for offline LSASS credential extraction
